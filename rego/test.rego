package licpol.testing

default allow_create = false

# Only allow license scopes that the actual caller have
# i.e. cannot add more scopes in a license request (data.json)
# than the scopes from JWT on caller request (input.json)
allow_create {
    input.method == "POST"
    input.path = ["license","generate", sawmill]

    iscopes := scopes_to_set(input.claims.scope)
    lscopes := scopes_to_set(data.license.scope)
    
    filtered := lscopes - iscopes

    count(filtered) == 0    
}

scopes_to_set(str) = {x |
  some i
  parts := split(str, " ")
  x := parts[i]
}
