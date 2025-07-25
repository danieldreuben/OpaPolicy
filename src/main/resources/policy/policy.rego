package scim.authz

default result = {
  "allow": false,
  "invalidClasses": []
}

is_admin if {
  input.roles[_] == "admin"
}

result = output if {
  # If user is admin, immediately allow
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


