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
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.eclipse.jetty.alpn.ALPN;
import org.junit.After;
import org.junit.Assert;

public class SSLSocketALPNTest extends AbstractALPNTest<SSLSocket>
{
    private SSLServerSocket acceptor;

    @After
    public void dispose() throws Exception
    {
        if (acceptor != null)
            acceptor.close();
    }

    @Override
    protected SSLResult<SSLSocket> performTLSHandshake(SSLResult<SSLSocket> handshake, ALPN.ClientProvider clientProvider, final ALPN.ServerProvider serverProvider) throws Exception
    {
        SSLContext sslContext = handshake == null ? SSLSupport.newSSLContext() : handshake.context;

        final CountDownLatch latch = new CountDownLatch(2);
        final SSLResult<SSLSocket> sslResult = new SSLResult<>();
        sslResult.context = sslContext;
        final int readTimeout = 5000;
        if (handshake == null)
        {
            acceptor = (SSLServerSocket)sslContext.getServerSocketFactory().createServerSocket();
            acceptor.bind(new InetSocketAddress("localhost", 0));
        }

        new Thread()
        {
            @Override
            public void run()
            {
                try
                {
                    SSLSocket serverSSLSocket = (SSLSocket)acceptor.accept();
                    System.err.println(serverSSLSocket);
                    sslResult.server = serverSSLSocket;

                    serverSSLSocket.setUseClientMode(false);
                    serverSSLSocket.setSoTimeout(readTimeout);
                    ALPN.put(serverSSLSocket, serverProvider);
                    serverSSLSocket.startHandshake();
                    latch.countDown();
                }
                catch (Exception x)
                {
                    x.printStackTrace();
                }
            }
        }.start();

        SSLSocket clientSSLSocket = (SSLSocket)sslContext.getSocketFactory().createSocket("localhost", acceptor.getLocalPort());
        sslResult.client = clientSSLSocket;
        latch.countDown();

        clientSSLSocket.setUseClientMode(true);
        clientSSLSocket.setSoTimeout(readTimeout);
        ALPN.put(clientSSLSocket, clientProvider);
        clientSSLSocket.startHandshake();

        Assert.assertTrue(latch.await(5, TimeUnit.SECONDS));
        return sslResult;
    }

    @Override
    protected void performTLSClose(SSLResult<SSLSocket> sslResult) throws Exception
    {
        sslResult.client.close();
        sslResult.server.close();
    }

    @Override
    protected void performDataExchange(SSLResult<SSLSocket> sslResult) throws Exception
    {
        SSLSocket clientSSLSocket = sslResult.client;
        SSLSocket serverSSLSocket = sslResult.server;

        byte[] data = new byte[1024];
        new Random().nextBytes(data);

        // Write the data.
        clientSSLSocket.getOutputStream().write(data);

        // Read the data.
        byte[] buffer = new byte[data.length];
        int read = 0;
        while (read < data.length)
            read += serverSSLSocket.getInputStream().read(buffer);

        // Write the data back.
        serverSSLSocket.getOutputStream().write(buffer, 0, read);

        // Read the echo.
        read = 0;
        while (read < data.length)
            read += clientSSLSocket.getInputStream().read(buffer);
    }

    @Override
    protected void performTLSRenegotiation(SSLResult<SSLSocket> sslResult, boolean client) throws Exception
    {
        if (client)
            sslResult.client.startHandshake();
        else
            sslResult.server.startHandshake();
    }

    @Override
    protected SSLSession getSSLSession(SSLResult<SSLSocket> sslResult, boolean client) throws Exception
    {
        SSLSocket sslSocket = client ? sslResult.client : sslResult.server;
        return sslSocket.getSession();
    }
}
