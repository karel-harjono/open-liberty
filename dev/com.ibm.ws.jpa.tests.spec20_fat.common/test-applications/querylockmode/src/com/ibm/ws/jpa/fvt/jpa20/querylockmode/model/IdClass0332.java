/*******************************************************************************
 * Copyright (c) 2019 IBM Corporation and others.
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

package com.ibm.ws.jpa.fvt.jpa20.querylockmode.model;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * <p>Id class of the Common Datamodel (which uses all the possible JPA 2.0 Annotations as described in the
 * <a href="http://www.j2ee.me/javaee/6/docs/api/javax/persistence/package-summary.html">javax.persistence documentation</a>)
 *
 *
 * <p><b>Notes:</b>
 * <ol>
 * <li>Per the JSR-317 spec (page 28), the primary key class:
 * <ul>
 * <li>Must be serializable
 * <li>Must define equals and hashCode methods
 * </ul>
 * </ol>
 */
public class IdClass0332 implements Serializable {

    private Long entity0332_id1;

    private Short entity0332_id2;

    private BigInteger entity0332_id3;

    public IdClass0332() {}

    public IdClass0332(Long id1,
                       Short id2,
                       BigInteger id3) {
        this.entity0332_id1 = id1;
        this.entity0332_id2 = id2;
        this.entity0332_id3 = id3;
    }

    @Override
    public String toString() {
        return (" IdClass0332: " +
                " entity0332_id1: " + getEntity0332_id1() +
                " entity0332_id2: " + getEntity0332_id2() +
                " entity0332_id3: " + getEntity0332_id3());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null)
            return false;
        if (!(o instanceof IdClass0332))
            return false;
        if (o == this)
            return true;
        IdClass0332 idClass = (IdClass0332) o;
        return (idClass.entity0332_id1 == entity0332_id1 &&
                idClass.entity0332_id2 == entity0332_id2 &&
                idClass.entity0332_id3 == entity0332_id3);
    }

    @Override
    public int hashCode() {
        int result = 0;
        result = result + entity0332_id1.hashCode();
        result = result + entity0332_id2.hashCode();
        result = result + entity0332_id3.hashCode();
        return result;
    }

    //----------------------------------------------------------------------------------------------
    // Persisent property accessor(s)
    //----------------------------------------------------------------------------------------------
    public Long getEntity0332_id1() {
        return entity0332_id1;
    }

    public Short getEntity0332_id2() {
        return entity0332_id2;
    }

    public BigInteger getEntity0332_id3() {
        return entity0332_id3;
    }
}
