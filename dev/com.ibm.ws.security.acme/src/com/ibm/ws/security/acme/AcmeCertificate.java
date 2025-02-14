/*******************************************************************************
 * Copyright (c) 2019, 2020 IBM Corporation and others.
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

package com.ibm.ws.security.acme;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Contains the certificate and certificate chain generated by the ACME CA
 * server, as well as the {@link KeyPair} that was used to sign the certificate
 * signing request (CSR).
 */
public class AcmeCertificate {

	/**
	 * The certificate returned from the ACME server.
	 */
	private final X509Certificate certificate;

	/**
	 * The certificate chain returned from the ACME server.
	 */
	private final List<X509Certificate> certificateChain;

	/**
	 * The {@link KeyPair} used to sign the CSR.
	 */
	private final KeyPair keyPair;

	/**
	 * Construct a new {@link AcmeCertificate}.
	 * 
	 * @param keyPair
	 *            The {@link KeyPair} used to sign the CSR.
	 * @param certificate
	 *            The leaf certificate generated by the ACME CA.
	 * @param certChain
	 *            The certificate chain generated by the ACME CA.
	 */
	public AcmeCertificate(KeyPair keyPair, X509Certificate certificate, List<X509Certificate> certChain) {
		this.keyPair = keyPair;
		this.certificate = certificate;
		this.certificateChain = certChain;
	}

	/**
	 * Get the leaf {@link X509Certificate} that was generated by the ACME CA.
	 * 
	 * @return The leaf certificate.
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	/**
	 * Get the certificate chain that was generated by the ACME CA server. This
	 * includes the leaf certificate, any intermediate certificates and
	 * optionally the root certificate.
	 * 
	 * @return The certificate chain.
	 */
	public List<X509Certificate> getCertificateChain() {
		return this.certificateChain;
	}

	/**
	 * The {@link KeyPair} that was used to sign the CSR request made to the
	 * ACME CA.
	 * 
	 * @return The {@link KeyPair}.
	 */
	public KeyPair getKeyPair() {
		return this.keyPair;
	}
}
