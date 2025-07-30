# Reference
Opa Website
https://www.openpolicyagent.org/docs

(optionally) Opa policies can be compiled from command-line
add to target/policy to run in Java
opa build -t wasm -e authz/allow policy.rego
tar -xvf bundle.tar.gz

Rego Playground
https://play.openpolicyagent.org

# Getting Started
--install opa command-line (required for compiling .rego files)
curl -L -o opa https://github.com/open-policy-agent/opa/releases/latest/download/opa_darwin_amd64

rename to opa.exe and add to path

--builds java and rego policy<p>
mvn clean install

--runs (aop) use-case with policy check<p>
mvn spring-boot:run 

See: policy test and resources/policy
https://github.com/danieldreuben/OpaPolicy/blob/main/src/main/resources/policy/policy.rego
