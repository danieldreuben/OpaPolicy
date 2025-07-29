package scim.authz

#default returns policy decision and invalid classes

default result = {
  "allow": false,
  "invalidClasses": []
}

#IT admin role has special consideration

is_admin if {
  input.roles[_] == "role.admin"  
  input["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].department == "IT"
}

#if 
result = output if {
  # If user is admin in IT department, immediately allow
  is_admin
  
  output := {
    "allow": true,
    "invalidClasses": []
  }
} else = output if {
  # Otherwise, check invalid classes
  invalids := [c |
    some i
    c := input.output.classes[i]
    not isValidClass(c)
  ]

  allow := count(invalids) == 0

  output := {
    "allow": allow,
    "invalidClasses": invalids
  }
}

isValidClass(c) if {
  some j
  input.claims.validationSet.validationList[j] == c
}
