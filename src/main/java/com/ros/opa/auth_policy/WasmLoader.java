package com.ros.opa.auth_policy;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

public class WasmLoader {

    private final String bundlePath;
    private final Map<String, byte[]> wasmCache = new HashMap<>();

    public WasmLoader(String bundlePath) {
        this.bundlePath = bundlePath;
    }

    /**
     * Loads and returns the given wasm policy file's bytes from the tar.gz bundle.
     * @param wasmFileName file name like "policy.wasm" or "authz_policy.wasm"
     * @return byte[] contents of the wasm file
     * @throws IOException if the file or bundle is missing
     */
    public byte[] getPolicy(String wasmFileName) throws IOException {
        if (wasmCache.containsKey(wasmFileName)) {
            return wasmCache.get(wasmFileName);
        }

        try (InputStream bundleStream = getClass().getClassLoader().getResourceAsStream(bundlePath)) {
            if (bundleStream == null) {
                throw new FileNotFoundException("WASM bundle not found at: " + bundlePath);
            }

            try (GZIPInputStream gis = new GZIPInputStream(bundleStream);
                 TarArchiveInputStream tis = new TarArchiveInputStream(gis)) {

                TarArchiveEntry entry;
                while ((entry = tis.getNextTarEntry()) != null) {
                    if (!entry.isDirectory() && entry.getName().endsWith(".wasm")) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = tis.read(buffer)) != -1) {
                            baos.write(buffer, 0, bytesRead);
                        }

                        byte[] wasmBytes = baos.toByteArray();
                        String fileName = entry.getName().substring(entry.getName().lastIndexOf("/") + 1);
                        System.out.println("loaded wasm " + fileName);
                        wasmCache.put(fileName, wasmBytes);
                    }
                }
            }
        }

        byte[] result = wasmCache.get(wasmFileName);
        if (result == null) {
            throw new FileNotFoundException("WASM file " + wasmFileName + " not found in bundle: " + bundlePath);
        }
        
        return result;
    }
}
