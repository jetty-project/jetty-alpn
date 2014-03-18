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

import java.io.IOException;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.eclipse.jetty.alpn.ALPN;

/**
 * Server that just accepts socket connections and selects spdy/3.
 * This is useful to test with Chromium to see if the implementation works.
 */
public class TestServer
{
    public static void main(String[] args) throws Exception
    {
        ALPN.debug = true;

        SSLContext context = SSLSupport.newSSLContext();
        SSLServerSocket server = (SSLServerSocket)context.getServerSocketFactory().createServerSocket(8443);
        while (true)
        {
            SSLSocket socket = (SSLSocket)server.accept();
            socket.setUseClientMode(false);
            ALPN.put(socket, new ALPN.ServerProvider()
            {
                @Override
                public void unsupported()
                {
                }

                @Override
                public String select(List<String> protocols)
                {
                    System.err.println("client protocols: " + protocols);
                    return "spdy/3";
                }
            });
            try
            {
                socket.startHandshake();
            }
            catch (IOException x)
            {
                x.printStackTrace();
            }
        }
    }
}
