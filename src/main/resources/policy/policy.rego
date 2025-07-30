package scim.authz

import rego.v1

default result = {
  "allow": false,
  "invalidClasses": [] 
}

method_permissions = {
  "createUser": ["admin", "manager"],
  "deleteUser": ["admin"],
  "getAllItems": ["admin", "auditor", "manager"]
}

# -------------------------------
# Check if any role from input.roles matches any required_roles for the input.method
has_valid_method_role if {
  required_roles := method_permissions[input.method]
  some idx1
  input.roles[idx1] == required_roles[_]
}

# -------------------------------
# Validate each class in input.output.classes
invalid_classes := [c |
  input.output.classes != null
  some i
  c := input.output.classes[i]
  not is_valid_class(c)
]

allow_classes if {
  count(invalid_classes) == 0
}

# -------------------------------
# Main result rule: both conditions must be true
result = output if {
  print("DEBUG: checking method role and class validation")
  has_valid_method_role
  allow_classes

  allow := true  # bind allow here since both conditions are true

  output := {
    "allow": allow,
    "invalidClasses": [],
    "debug": {
      "input_method": input.method,
      "input_roles": input.roles,
      "required_roles": method_permissions[input.method],
      "has_valid_method_role": true
    }    
  }
} else = output if {
  print("DEBUG: denying access; collecting invalid classes")
  output := {
    "allow": false,
    "invalidClasses": invalid_classes,
    "debug": {
      "input_method": input.method,
      "input_roles": input.roles,
      "required_roles": method_permissions[input.method],
      "has_valid_method_role": false   
    } 
  }
}

# -------------------------------
# Helper: is class valid?
is_valid_class(c) if {
  c == input.claims.validationSet.validationList[_]
}

