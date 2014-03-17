//
//  ========================================================================
//  Copyright (c) 1995-2014 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.mortbay.jetty.alpn;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

import org.eclipse.jetty.alpn.ALPN;
import org.junit.Assert;
import org.junit.Test;

public class SSLEngineALPNTest
{
    @Test
    public void testSSLEngine() throws Exception
    {
        ALPN.debug = true;

        final SSLContext context = SSLSupport.newSSLContext();

        final int readTimeout = 5000;
        final String data = "data";
        final String protocolName = "test";
        final AtomicReference<CountDownLatch> latch = new AtomicReference<>(new CountDownLatch(4));
        final ServerSocketChannel server = ServerSocketChannel.open();
        server.bind(new InetSocketAddress("localhost", 0));
        new Thread()
        {
            @Override
            public void run()
            {
                try
                {
                    SSLEngine sslEngine = context.createSSLEngine();
                    sslEngine.setUseClientMode(false);
                    ALPN.put(sslEngine, new ALPN.ServerProvider()
                    {
                        @Override
                        public void unsupported()
                        {
                        }

                        @Override
                        public String select(List<String> protocols)
                        {
                            Assert.assertEquals(1, protocols.size());
                            String protocol = protocols.get(0);
                            Assert.assertEquals(protocolName, protocol);
                            latch.get().countDown();
                            return protocol;
                        }
                    });
                    ByteBuffer encrypted = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
                    ByteBuffer decrypted = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());

                    SocketChannel socket = server.accept();
                    socket.socket().setSoTimeout(readTimeout);

                    sslEngine.beginHandshake();
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, sslEngine.getHandshakeStatus());

                    // Read ClientHello
                    socket.read(encrypted);
                    encrypted.flip();
                    SSLEngineResult result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
                    sslEngine.getDelegatedTask().run();
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

                    // Generate and write ServerHello
                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    // Read up to Finished
                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
                    sslEngine.getDelegatedTask().run();
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, sslEngine.getHandshakeStatus());
                    if (!encrypted.hasRemaining())
                    {
                        encrypted.clear();
                        socket.read(encrypted);
                        encrypted.flip();
                    }
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
                    if (!encrypted.hasRemaining())
                    {
                        encrypted.clear();
                        socket.read(encrypted);
                        encrypted.flip();
                    }
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());

                    if (SSLEngineResult.HandshakeStatus.NEED_UNWRAP == result.getHandshakeStatus())
                    {
                        if (!encrypted.hasRemaining())
                        {
                            encrypted.clear();
                            socket.read(encrypted);
                            encrypted.flip();
                        }
                        result = sslEngine.unwrap(encrypted, decrypted);
                        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    }
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());

                    // Generate and write ChangeCipherSpec
                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);
                    // Generate and write Finished
                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.FINISHED, result.getHandshakeStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, sslEngine.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    // Read data
                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

                    // Echo the data back
                    encrypted.clear();
                    decrypted.flip();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    // Read re-handshake
                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
                    sslEngine.getDelegatedTask().run();
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
                    sslEngine.getDelegatedTask().run();
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, sslEngine.getHandshakeStatus());
                    if (!encrypted.hasRemaining())
                    {
                        encrypted.clear();
                        socket.read(encrypted);
                        encrypted.flip();
                    }
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, sslEngine.getHandshakeStatus());
                    if (!encrypted.hasRemaining())
                    {
                        encrypted.clear();
                        socket.read(encrypted);
                        encrypted.flip();
                    }
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());

                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);
                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.FINISHED, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    // Read more data
                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

                    // Echo the data back
                    encrypted.clear();
                    decrypted.flip();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);

                    // TODO
                    // Re-handshake
//                    sslEngine.beginHandshake();

                    // Close
                    encrypted.clear();
                    socket.read(encrypted);
                    encrypted.flip();
                    decrypted.clear();
                    result = sslEngine.unwrap(encrypted, decrypted);
                    Assert.assertSame(SSLEngineResult.Status.CLOSED, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
                    encrypted.clear();
                    Assert.assertEquals(-1, socket.read(encrypted));
                    encrypted.clear();
                    result = sslEngine.wrap(decrypted, encrypted);
                    Assert.assertSame(SSLEngineResult.Status.CLOSED, result.getStatus());
                    Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
                    encrypted.flip();
                    socket.write(encrypted);
                    socket.close();
                }
                catch (Exception x)
                {
                    x.printStackTrace();
                }
            }
        }.start();

        SSLEngine sslEngine = context.createSSLEngine();
        sslEngine.setUseClientMode(true);
        ALPN.put(sslEngine, new ALPN.ClientProvider()
        {
            @Override
            public boolean supports()
            {
                latch.get().countDown();
                return true;
            }

            @Override
            public void unsupported()
            {
            }

            @Override
            public List<String> protocols()
            {
                latch.get().countDown();
                return Arrays.asList(protocolName);
            }

            @Override
            public void selected(String protocol)
            {
                Assert.assertEquals(protocolName, protocol);
                latch.get().countDown();
            }
        });
        ByteBuffer encrypted = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
        ByteBuffer decrypted = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());

        SocketChannel client = SocketChannel.open(server.getLocalAddress());
        client.socket().setSoTimeout(readTimeout);

        sslEngine.beginHandshake();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

        // Generate and write ClientHello
        SSLEngineResult result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);

        // Read Server Hello
        while (sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
        {
            encrypted.clear();
            client.read(encrypted);
            encrypted.flip();
            result = sslEngine.unwrap(encrypted, decrypted);
            Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK)
                sslEngine.getDelegatedTask().run();
        }
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

        // Generate and write ClientKeyExchange
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);
        // Generate and write ChangeCipherSpec
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);
        // Generate and write Finished
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        encrypted.flip();
        client.write(encrypted);

        if (SSLEngineResult.HandshakeStatus.NEED_WRAP == result.getHandshakeStatus())
        {
            encrypted.clear();
            result = sslEngine.wrap(decrypted, encrypted);
            Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
            encrypted.flip();
            client.write(encrypted);
        }
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());

        // Read ChangeCipherSpec
        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        // Read Finished
        if (!encrypted.hasRemaining())
        {
            encrypted.clear();
            client.read(encrypted);
            encrypted.flip();
        }
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.FINISHED, result.getHandshakeStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, sslEngine.getHandshakeStatus());

        Assert.assertTrue(latch.get().await(5, TimeUnit.SECONDS));

        // Now try to write real data to see if it works
        encrypted.clear();
        result = sslEngine.wrap(ByteBuffer.wrap(data.getBytes("UTF-8")), encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);

        // Read echo
        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

        decrypted.flip();
        Assert.assertEquals(data, Charset.forName("UTF-8").decode(decrypted).toString());

        // Perform a re-handshake, and verify that ALPN does not trigger
        latch.set(new CountDownLatch(4));
        sslEngine.beginHandshake();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);

        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_TASK, result.getHandshakeStatus());
        sslEngine.getDelegatedTask().run();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());

        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);

        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        if (!encrypted.hasRemaining())
        {
            encrypted.clear();
            client.read(encrypted);
            encrypted.flip();
        }
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.FINISHED, result.getHandshakeStatus());

        // Re-handshake completed, check ALPN was not invoked
        Assert.assertEquals(4, latch.get().getCount());

        // Write more data
        encrypted.clear();
        result = sslEngine.wrap(ByteBuffer.wrap(data.getBytes("UTF-8")), encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);

        // Read echo
        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

        decrypted.flip();
        Assert.assertEquals(data, Charset.forName("UTF-8").decode(decrypted).toString());

        // Close
        sslEngine.closeOutbound();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, sslEngine.getHandshakeStatus());
        encrypted.clear();
        result = sslEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.CLOSED, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());
        encrypted.flip();
        client.write(encrypted);
        client.shutdownOutput();
        encrypted.clear();
        client.read(encrypted);
        encrypted.flip();
        decrypted.clear();
        result = sslEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.CLOSED, result.getStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
        client.close();

        server.close();
    }
}
