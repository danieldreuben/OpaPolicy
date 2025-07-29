Opa Website
https://www.openpolicyagent.org/docs

Project requires Opa command-line to compile Policy files (see also maven plugin in project pom.xml)
https://www.openpolicyagent.org/docs?current-os=windows#1-download-opa

(optionally) Opa policies can be compiled from command-line
add to target/policy to run in Java
opa build -t wasm -e authz/allow policy.rego
tar -xvf bundle.tar.gz

# Getting Started
mvn build (clean, install, test, compile)
See: policy test and resources/policy

https://github.com/danieldreuben/OpaPolicy/blob/main/src/main/resources/policy/policy.rego
