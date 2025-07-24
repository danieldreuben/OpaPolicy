package scim.authz

default result = {
  "allow": false,
  "invalidClasses": []
}

result = output if {
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


