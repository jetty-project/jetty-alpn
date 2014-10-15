/*
 * Copyright (c) 2014, Mort Bay Consulting Pty. Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Mort Bay Consulting designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Mort Bay Consulting in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 */

package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLProtocolException;

public class ALPNExtension extends HelloExtension
{
    private static final int ID = ExtensionType.EXT_ALPN.id;

    private final List<String> protocols = new ArrayList<>();
    private final byte[] content;

    public ALPNExtension(List<String> protocols) throws SSLProtocolException
    {
        super(ExtensionType.get(ID));
        this.protocols.addAll(protocols);
        content = init();
    }

    public ALPNExtension(HandshakeInStream input, int length) throws IOException
    {
        super(ExtensionType.get(ID));
        length = input.getInt16();
        while (length > 0)
        {
            byte[] protocolBytes = input.getBytes8();
            protocols.add(new String(protocolBytes, StandardCharsets.UTF_8));
            length -= 1 + protocolBytes.length;
        }
        content = init();
    }

    private byte[] init() throws SSLProtocolException
    {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (String protocol : protocols)
        {
            byte[] protocolBytes = protocol.getBytes(StandardCharsets.UTF_8);
            int length = protocolBytes.length;
            if (length > 255)
                throw new SSLProtocolException("Protocol name too long: " + protocol);
            bytes.write(length);
            bytes.write(protocolBytes, 0, length);
        }
        byte[] protocolsBytes = bytes.toByteArray();
        byte[] result = new byte[2 + protocolsBytes.length];
        result[0] = (byte)((protocolsBytes.length & 0xFF00) >> 8);
        result[1] = (byte)(protocolsBytes.length & 0xFF);
        System.arraycopy(protocolsBytes, 0, result, 2, protocolsBytes.length);
        return result;
    }

    public List<String> getProtocols()
    {
        return protocols;
    }

    @Override
    int length()
    {
        return 2 + 2 + content.length;
    }

    @Override
    void send(HandshakeOutStream out) throws IOException
    {
        out.putInt16(ID);
        out.putInt16(content.length);
        out.write(content, 0, content.length);
    }

    @Override
    public String toString()
    {
        return String.format("Extension %s, protocols: %s", type, protocols);
    }
}
