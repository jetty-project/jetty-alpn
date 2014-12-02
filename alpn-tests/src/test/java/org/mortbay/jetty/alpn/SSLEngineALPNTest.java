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

import java.nio.ByteBuffer;
import java.util.Random;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import org.eclipse.jetty.alpn.ALPN;
import org.junit.Assert;

public class SSLEngineALPNTest extends AbstractALPNTest<SSLEngine>
{
    @Override
    protected SSLResult<SSLEngine> performTLSHandshake(SSLResult<SSLEngine> handshake, ALPN.ClientProvider clientProvider, ALPN.ServerProvider serverProvider) throws Exception
    {
        SSLContext sslContext = handshake == null ? SSLSupport.newSSLContext() : handshake.context;
        SSLResult<SSLEngine> sslResult = new SSLResult<>();
        sslResult.context = sslContext;
        // Use host and port to allow for session resumption.
        int randomPort = new Random().nextInt(20000) + 10000;
        int clientPort = handshake == null ? randomPort : handshake.client.getPeerPort();
        SSLEngine clientSSLEngine = sslContext.createSSLEngine("localhost", clientPort);
        sslResult.client = clientSSLEngine;
        clientSSLEngine.setUseClientMode(true);
        int serverPort = handshake == null ? randomPort + 1 : handshake.server.getPeerPort();
        SSLEngine serverSSLEngine = sslContext.createSSLEngine("localhost", serverPort);
        sslResult.server = serverSSLEngine;
        serverSSLEngine.setUseClientMode(false);

        ByteBuffer encrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getPacketBufferSize());
        ByteBuffer decrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getApplicationBufferSize());

        ALPN.put(clientSSLEngine, clientProvider);
        clientSSLEngine.beginHandshake();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, clientSSLEngine.getHandshakeStatus());

        ALPN.put(serverSSLEngine, serverProvider);
        serverSSLEngine.beginHandshake();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, serverSSLEngine.getHandshakeStatus());

        // Generate and write ClientHello
        wrap(clientSSLEngine, decrypted, encrypted);

        // Read the ClientHello
        unwrap(serverSSLEngine, encrypted, decrypted);

        // Generate and write ServerHello (and other messages)
        wrap(serverSSLEngine, decrypted, encrypted);

        // Read the ServerHello (and other messages)
        unwrap(clientSSLEngine, encrypted, decrypted);

        // Generate and write ClientKeyExchange, ChangeCipherSpec and Finished
        wrap(clientSSLEngine, decrypted, encrypted);

        // Read ClientKeyExchange, ChangeCipherSpec and Finished
        unwrap(serverSSLEngine, encrypted, decrypted);

        // Generate and write ChangeCipherSpec and Finished
        wrap(serverSSLEngine, decrypted, encrypted);

        // Read ChangeCipherSpec and Finished
        unwrap(clientSSLEngine, encrypted, decrypted);

        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientSSLEngine.getHandshakeStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverSSLEngine.getHandshakeStatus());

        return sslResult;
    }

    @Override
    protected void performTLSClose(SSLResult<SSLEngine> sslResult) throws Exception
    {
        SSLEngine clientSSLEngine = sslResult.client;
        SSLEngine serverSSLEngine = sslResult.server;

        ByteBuffer encrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getPacketBufferSize());
        ByteBuffer decrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getApplicationBufferSize());

        clientSSLEngine.closeOutbound();
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, clientSSLEngine.getHandshakeStatus());

        wrap(clientSSLEngine, decrypted, encrypted);

        unwrap(serverSSLEngine, encrypted, decrypted);

        wrap(serverSSLEngine, decrypted, encrypted);

        unwrap(clientSSLEngine, encrypted, decrypted);

        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientSSLEngine.getHandshakeStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverSSLEngine.getHandshakeStatus());
    }

    @Override
    protected void performDataExchange(SSLResult<SSLEngine> sslResult) throws Exception
    {
        SSLEngine clientSSLEngine = sslResult.client;
        SSLEngine serverSSLEngine = sslResult.server;

        ByteBuffer encrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getPacketBufferSize());
        ByteBuffer decrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getApplicationBufferSize());

        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientSSLEngine.getHandshakeStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverSSLEngine.getHandshakeStatus());

        byte[] data = new byte[1024];
        new Random().nextBytes(data);

        // Write the data.
        encrypted.clear();
        decrypted.clear();
        decrypted.put(data).flip();
        SSLEngineResult result = clientSSLEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());

        // Read the data.
        encrypted.flip();
        decrypted.clear();
        result = serverSSLEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());

        // Write the data back.
        encrypted.clear();
        decrypted.flip();
        result = serverSSLEngine.wrap(decrypted, encrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());

        // Read the echo.
        encrypted.flip();
        decrypted.clear();
        result = clientSSLEngine.unwrap(encrypted, decrypted);
        Assert.assertSame(SSLEngineResult.Status.OK, result.getStatus());
    }

    @Override
    protected void performTLSRenegotiation(SSLResult<SSLEngine> sslResult, boolean client) throws Exception
    {
        SSLEngine clientSSLEngine = sslResult.client;
        SSLEngine serverSSLEngine = sslResult.server;

        ByteBuffer encrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getPacketBufferSize());
        ByteBuffer decrypted = ByteBuffer.allocate(clientSSLEngine.getSession().getApplicationBufferSize());

        if (client)
        {
            clientSSLEngine.beginHandshake();
            Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, clientSSLEngine.getHandshakeStatus());
        }
        else
        {
            serverSSLEngine.beginHandshake();
            Assert.assertSame(SSLEngineResult.HandshakeStatus.NEED_WRAP, serverSSLEngine.getHandshakeStatus());

            wrap(serverSSLEngine, decrypted, encrypted);

            unwrap(clientSSLEngine, encrypted, decrypted);
        }

        wrap(clientSSLEngine, decrypted, encrypted);

        unwrap(serverSSLEngine, encrypted, decrypted);

        wrap(serverSSLEngine, decrypted, encrypted);

        unwrap(clientSSLEngine, encrypted, decrypted);

        wrap(clientSSLEngine, decrypted, encrypted);

        unwrap(serverSSLEngine, encrypted, decrypted);

        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientSSLEngine.getHandshakeStatus());
        Assert.assertSame(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverSSLEngine.getHandshakeStatus());
    }

    @Override
    protected SSLSession getSSLSession(SSLResult<SSLEngine> sslResult, boolean client) throws Exception
    {
        SSLEngine sslEngine = client ? sslResult.client : sslResult.server;
        return sslEngine.getSession();
    }

    private void wrap(SSLEngine sslEngine, ByteBuffer decrypted, ByteBuffer encrypted) throws Exception
    {
        encrypted.clear();
        ByteBuffer tmp = ByteBuffer.allocate(encrypted.capacity());
        while (true)
        {
            encrypted.clear();
            SSLEngineResult result = sslEngine.wrap(decrypted, encrypted);
            SSLEngineResult.Status status = result.getStatus();
            if (status != SSLEngineResult.Status.OK && status != SSLEngineResult.Status.CLOSED)
                throw new AssertionError(status.toString());
            encrypted.flip();
            tmp.put(encrypted);
            if (result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP)
            {
                tmp.flip();
                encrypted.clear();
                encrypted.put(tmp).flip();
                return;
            }
        }
    }

    private void unwrap(SSLEngine sslEngine, ByteBuffer encrypted, ByteBuffer decrypted) throws Exception
    {
        decrypted.clear();
        while (true)
        {
            decrypted.clear();
            SSLEngineResult result = sslEngine.unwrap(encrypted, decrypted);
            SSLEngineResult.Status status = result.getStatus();
            if (status != SSLEngineResult.Status.OK && status != SSLEngineResult.Status.CLOSED)
                throw new AssertionError(status.toString());
            SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
            if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK)
            {
                sslEngine.getDelegatedTask().run();
                handshakeStatus = sslEngine.getHandshakeStatus();
            }
            if (handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
                return;
        }
    }
}
