/*******************************************************************************
 * Copyright (c) 2015 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
/*
 * Some of the code was derived from code supplied by the Apache Software Foundation licensed under the Apache License, Version 2.0.
 */

package com.ibm.ws.transport.iiop.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

public class DERSequence
    extends ASN1Sequence
{
    /**
     * create an empty sequence
     */
    public DERSequence()
    {
    }

    /**
     * create a sequence containing one object
     */
    public DERSequence(
        DEREncodable    obj)
    {
        this.addObject(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     */
    public DERSequence(
        DEREncodableVector   v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            this.addObject(v.get(i));
        }
    }

    /**
     * create a sequence containing an array of objects.
     */
    public DERSequence(
        ASN1Encodable[]   a)
    {
        for (int i = 0; i != a.length; i++)
        {
            this.addObject(a[i]);
        }
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputing SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        DEROutputStream out)
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        Enumeration             e = this.getObjects();

        while (e.hasMoreElements())
        {
            Object    obj = e.nextElement();

            dOut.writeObject(obj);
        }

        dOut.close();

        byte[]  bytes = bOut.toByteArray();

        out.writeEncoded(SEQUENCE | CONSTRUCTED, bytes);
    }
}
