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

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import org.eclipse.jetty.alpn.ALPN;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractALPNTest<T>
{
    protected abstract SSLResult<T> performTLSHandshake(SSLResult<T> handshake, ALPN.ClientProvider clientProvider, ALPN.ServerProvider serverProvider) throws Exception;

    protected abstract void performTLSClose(SSLResult<T> sslResult) throws Exception;

    protected abstract void performDataExchange(SSLResult<T> sslResult) throws Exception;

    protected abstract void performTLSRenegotiation(SSLResult<T> sslResult, boolean client) throws Exception;

    protected abstract SSLSession getSSLSession(SSLResult<T> sslResult, boolean client) throws Exception;

    @Before
    public void prepare() throws Exception
    {
        Assert.assertNull("ALPN classes must be in the bootclasspath.", ALPN.class.getClassLoader());
        ALPN.debug = true;
    }

    @Test
    public void testALPNSuccessful() throws Exception
    {
        final String protocolName = "test";
        final CountDownLatch latch = new CountDownLatch(3);
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
        {
            @Override
            public List<String> protocols()
            {
                latch.countDown();
                return Arrays.asList(protocolName);
            }

            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public void selected(String protocol)
            {
                Assert.assertEquals(protocolName, protocol);
                latch.countDown();
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public String select(List<String> protocols)
            {
                Assert.assertEquals(1, protocols.size());
                String protocol = protocols.get(0);
                Assert.assertEquals(protocolName, protocol);
                latch.countDown();
                return protocol;
            }
        };
        SSLResult<T> sslResult = performTLSHandshake(null, clientProvider, serverProvider);
        Assert.assertTrue(latch.await(5, TimeUnit.SECONDS));

        // Verify that we can exchange data without errors.
        performDataExchange(sslResult);

        performTLSClose(sslResult);
    }

    @Test
    public void testServerDoesNotSendALPN() throws Exception
    {
        final String protocolName = "test";
        final CountDownLatch latch = new CountDownLatch(3);
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
        {
            @Override
            public List<String> protocols()
            {
                latch.countDown();
                return Arrays.asList(protocolName);
            }

            @Override
            public void unsupported()
            {
                latch.countDown();
            }

            @Override
            public void selected(String protocol)
            {
                Assert.fail();
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public String select(List<String> protocols)
            {
                Assert.assertEquals(1, protocols.size());
                String protocol = protocols.get(0);
                Assert.assertEquals(protocolName, protocol);
                latch.countDown();
                // By returning null, the server won't send the ALPN extension.
                return null;
            }
        };
        SSLResult<T> sslResult = performTLSHandshake(null, clientProvider, serverProvider);
        Assert.assertTrue(latch.await(5, TimeUnit.SECONDS));

        // Verify that we can exchange data without errors.
        performDataExchange(sslResult);

        performTLSClose(sslResult);
    }

    @Test
    public void testServerThrowsException() throws Exception
    {
        final String protocolName = "test";
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
        {
            @Override
            public List<String> protocols()
            {
                return Arrays.asList(protocolName);
            }

            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public void selected(String protocol)
            {
                Assert.fail();
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public String select(List<String> protocols) throws SSLException
            {
                // By throwing, the server will close the connection.
                throw new SSLHandshakeException("explicitly_thrown_by_test");
            }
        };

        try
        {
            performTLSHandshake(null, clientProvider, serverProvider);
            Assert.fail();
        }
        catch (SSLHandshakeException x)
        {
            // Expected.
        }
    }

    @Test
    public void testClientThrowsException() throws Exception
    {
        final String protocolName = "test";
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
        {
            @Override
            public List<String> protocols()
            {
                return Arrays.asList(protocolName);
            }

            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public void selected(String protocol) throws SSLException
            {
                if (!protocolName.equals(protocol))
                    throw new SSLHandshakeException("explicitly_thrown_by_test");
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                Assert.fail();
            }

            @Override
            public String select(List<String> protocols) throws SSLException
            {
                // Return a protocol that the client does not support.
                return "boom." + protocolName;
            }
        };

        try
        {
            performTLSHandshake(null, clientProvider, serverProvider);
            Assert.fail();
        }
        catch (SSLHandshakeException x)
        {
            // Expected.
        }
    }

    @Test
    public void testClientTLSRenegotiation() throws Exception
    {
        testTLSRenegotiation(true);
    }

    @Test
    public void testServerTLSRenegotiation() throws Exception
    {
        testTLSRenegotiation(false);
    }

    private void testTLSRenegotiation(boolean client) throws Exception
    {
        final String protocolName = "test";
        final AtomicReference<CountDownLatch> latch = new AtomicReference<>(new CountDownLatch(3));
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
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
                latch.get().countDown();
                Assert.fail();
            }

            @Override
            public void selected(String protocol)
            {
                Assert.assertEquals(protocolName, protocol);
                latch.get().countDown();
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                latch.get().countDown();
                Assert.fail();
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
        };
        SSLResult<T> sslResult = performTLSHandshake(null, clientProvider, serverProvider);
        Assert.assertTrue(latch.get().await(5, TimeUnit.SECONDS));

        // Verify that we can exchange data without errors.
        performDataExchange(sslResult);

        latch.set(new CountDownLatch(1));
        performTLSRenegotiation(sslResult, client);

        // The data exchange may trigger the completion of the TLS renegotiation.
        performDataExchange(sslResult);

        // ALPN must not trigger.
        Assert.assertFalse(latch.get().await(1, TimeUnit.SECONDS));

        performTLSClose(sslResult);
    }

    @Test
    public void testTLSSessionResumption() throws Exception
    {
        final String protocolName = "test";
        final AtomicReference<CountDownLatch> latch = new AtomicReference<>();
        ALPN.ClientProvider clientProvider = new ALPN.ClientProvider()
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
                Assert.fail();
            }

            @Override
            public void selected(String protocol)
            {
                Assert.assertEquals(protocolName, protocol);
                latch.get().countDown();
            }
        };
        ALPN.ServerProvider serverProvider = new ALPN.ServerProvider()
        {
            @Override
            public void unsupported()
            {
                Assert.fail();
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
        };

        // First TLS handshake.
        latch.set(new CountDownLatch(3));
        SSLResult<T> sslResult = performTLSHandshake(null, clientProvider, serverProvider);
        Assert.assertTrue(latch.get().await(5, TimeUnit.SECONDS));
        SSLSession clientSession1 = getSSLSession(sslResult, true);
        SSLSession serverSession1 = getSSLSession(sslResult, false);
        // Must close the first session before starting the second one.
        performTLSClose(sslResult);

        // Second TLS handshake.
        latch.set(new CountDownLatch(3));
        sslResult = performTLSHandshake(sslResult, clientProvider, serverProvider);
        Assert.assertTrue(latch.get().await(5, TimeUnit.SECONDS));

        Assert.assertSame(clientSession1, getSSLSession(sslResult, true));
        Assert.assertSame(serverSession1, getSSLSession(sslResult, false));

        performTLSClose(sslResult);
    }

    public static class SSLResult<S>
    {
        public SSLContext context;
        public S client;
        public S server;
    }
}
