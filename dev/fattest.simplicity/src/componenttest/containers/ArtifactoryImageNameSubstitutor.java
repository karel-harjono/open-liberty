/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package componenttest.containers;

import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.ImageNameSubstitutor;

import com.ibm.websphere.simplicity.log.Log;

import componenttest.topology.utils.ExternalTestService;

/**
 * An image name substituter is configured in testcontainers.properties and will transform docker image names.
 * Here we use it to apply a private registry prefix so that in remote builds we use an internal mirror
 * of Docker Hub, instead of downloading from Docker Hub in each build which causes rate limiting issues.
 */
public class ArtifactoryImageNameSubstitutor extends ImageNameSubstitutor {

    private static final Class<?> c = ArtifactoryImageNameSubstitutor.class;

    @Override
    public DockerImageName apply(DockerImageName original) {
        // If we are using local docker, or a programmatically built image, or a registry was explicitly set,
        // we don't want to perform any substitution -- just return the original
        if (!ExternalTestServiceDockerClientStrategy.useRemoteDocker() ||
            isSyntheticImage(original) ||
            (original.getRegistry() != null && !original.getRegistry().isEmpty())) {
            return original;
        }

        // Using remote docker, need to substitute image name to use private registry
        String privateImage = getPrivateRegistry() + '/' + original.asCanonicalNameString();
        Log.info(c, "apply", "Swapping docker image name from " + original.asCanonicalNameString() + " --> " + privateImage);
        return DockerImageName.parse(privateImage).asCompatibleSubstituteFor(original);
    }

    @Override
    protected String getDescription() {
        return "private artifactory registry substitutor";
    }

    /**
     * Docker images that are programmatically constructed at runtime (usually with ImageFromDockerfile)
     * will error out with a 404 if we attempt to do a docker pull from an Artifactory mirror registry.
     * To work around this issue, we will avoid image name substitution for image names that appear to be programmatically
     * generated by Testcontainers. FATs that use ImageFromDockerfile should consider using dedicated images
     * instead of programmatic construction (see com.ibm.ws.cloudant_fat/publish/files/couchdb-ssl/ for an example)
     */
    private static boolean isSyntheticImage(DockerImageName dockerImage) {
        String name = dockerImage.asCanonicalNameString();
        boolean isSynthetic = name.startsWith("testcontainers/") && name.endsWith("latest");
        if (isSynthetic) {
            Log.warning(c, "WARNING: Cannot use private registry for programmatically built image " + name +
                           ". Consider using a pre-built image instead.");
        }
        return isSynthetic;
    }

    static String getPrivateRegistry() {
        String artifactoryServer = System.getProperty("fat.test.artifactory.download.server");
        if (artifactoryServer == null || artifactoryServer.isEmpty() || artifactoryServer.startsWith("${"))
            throw new IllegalStateException("No private registry configured. System property 'fat.test.artifactory.download.server' was: " + artifactoryServer);
        if (artifactoryServer.startsWith("na.") || artifactoryServer.startsWith("eu."))
            artifactoryServer = artifactoryServer.substring(3);
        return "wasliberty-docker-remote." + artifactoryServer;
    }

    static String getPrivateRegistryAuthToken() {
        try {
            String token = ExternalTestService.getProperty("docker-hub-mirror/auth-token");
            if (token == null || token.isEmpty() || token.startsWith("${"))
                throw new IllegalStateException("Unable to locate private registry auth token.");
            Log.info(c, "getPrivateRegistryAuthToken", "Got auth token starting with: " + token.substring(0, 4) + "....");
            return token;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
