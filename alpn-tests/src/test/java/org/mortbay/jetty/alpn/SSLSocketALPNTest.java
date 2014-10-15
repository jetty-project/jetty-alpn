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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.eclipse.jetty.alpn.ALPN;
import org.junit.Assert;
import org.junit.Test;

public class SSLSocketALPNTest
{
    @Test
    public void testNegotiationSuccessful() throws Exception
    {
        ALPN.debug = true;

        SSLContext context = SSLSupport.newSSLContext();

        final int readTimeout = 50000;
        final String data = "data";
        final String protocolName = "test";
        final AtomicReference<CountDownLatch> latch = new AtomicReference<>(new CountDownLatch(3));
        final SSLServerSocket server = (SSLServerSocket)context.getServerSocketFactory().createServerSocket();
        server.bind(new InetSocketAddress("localhost", 0));
        final CountDownLatch handshakeLatch = new CountDownLatch(2);
        new Thread()
        {
            @Override
            public void run()
            {
                try
                {
                    final SSLSocket socket = (SSLSocket)server.accept();
                    socket.setUseClientMode(false);
                    socket.setSoTimeout(readTimeout);
                    ALPN.put(socket, new ALPN.ServerProvider()
                    {
                        @Override
                        public void unsupported()
                        {
                            ALPN.remove(socket);
                        }

                        @Override
                        public String select(List<String> protocols)
                        {
                            ALPN.remove(socket);
                            Assert.assertEquals(1, protocols.size());
                            String protocol = protocols.get(0);
                            Assert.assertEquals(protocolName, protocol);
                            latch.get().countDown();
                            return protocol;
                        }
                    });
                    socket.addHandshakeCompletedListener(event -> handshakeLatch.countDown());
                    socket.startHandshake();

                    InputStream serverInput = socket.getInputStream();
                    for (int i = 0; i < data.length(); ++i)
                    {
                        int read = serverInput.read();
                        Assert.assertEquals(data.charAt(i), read);
                    }

                    OutputStream serverOutput = socket.getOutputStream();
                    serverOutput.write(data.getBytes("UTF-8"));
                    serverOutput.flush();

                    for (int i = 0; i < data.length(); ++i)
                    {
                        int read = serverInput.read();
                        Assert.assertEquals(data.charAt(i), read);
                    }

                    serverOutput.write(data.getBytes("UTF-8"));
                    serverOutput.flush();

                    // Re-handshake
                    socket.startHandshake();

                    for (int i = 0; i < data.length(); ++i)
                    {
                        int read = serverInput.read();
                        Assert.assertEquals(data.charAt(i), read);
                    }

                    serverOutput.write(data.getBytes("UTF-8"));
                    serverOutput.flush();

                    Assert.assertEquals(4, latch.get().getCount());

                    socket.close();
                }
                catch (Exception x)
                {
                    x.printStackTrace();
                }
            }
        }.start();

        final SSLSocket client = (SSLSocket)context.getSocketFactory().createSocket("localhost", server.getLocalPort());
        client.setUseClientMode(true);
        client.setSoTimeout(readTimeout);
        ALPN.put(client, new ALPN.ClientProvider()
        {
            @Override
            public List<String> protocols()
            {
                latch.get().countDown();
                return Arrays.asList(protocolName);
            }

            @Override
            public void unsupported()
            {
                ALPN.remove(client);
            }

            @Override
            public void selected(String protocol)
            {
                ALPN.remove(client);
                Assert.assertEquals(protocolName, protocol);
                latch.get().countDown();
            }
        });

        client.addHandshakeCompletedListener(event -> handshakeLatch.countDown());
        client.startHandshake();

        Assert.assertTrue(latch.get().await(5, TimeUnit.SECONDS));
        Assert.assertTrue(handshakeLatch.await(5, TimeUnit.SECONDS));

        // Check whether we can write real data to the connection
        OutputStream clientOutput = client.getOutputStream();
        clientOutput.write(data.getBytes("UTF-8"));
        clientOutput.flush();

        InputStream clientInput = client.getInputStream();
        for (int i = 0; i < data.length(); ++i)
        {
            int read = clientInput.read();
            Assert.assertEquals(data.charAt(i), read);
        }

        // Re-handshake
        latch.set(new CountDownLatch(4));
        client.startHandshake();
        Assert.assertEquals(4, latch.get().getCount());

        clientOutput.write(data.getBytes("UTF-8"));
        clientOutput.flush();

        for (int i = 0; i < data.length(); ++i)
        {
            int read = clientInput.read();
            Assert.assertEquals(data.charAt(i), read);
        }

        clientOutput.write(data.getBytes("UTF-8"));
        clientOutput.flush();

        for (int i = 0; i < data.length(); ++i)
        {
            int read = clientInput.read();
            Assert.assertEquals(data.charAt(i), read);
        }

        int read = clientInput.read();
        Assert.assertEquals(-1, read);

        client.close();

        server.close();
    }
}
