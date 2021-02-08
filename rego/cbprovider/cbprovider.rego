package cbprovider

# Errors to be skipped
# If present in report as well it will not be skipped
# (report overrides skip)
skip[dp] {
	my := data.target[dp]
	my == "$error"   
    
    matchSkip(dp)
    
    not matchReport(dp)
}

# Errors to be skipped when out of range
skip[dp] {
	my := data.target[dp]
	my != "$error"   
    
    matchSkip(dp)
    
    not matchReport(dp)
    
    range := get_range(dp)
	not in_range(my, range[0], range[1])    
}


# Errors to be reported
# If matches both in skip and report -> report overrides skip
report[dp] {
	my := data.target[dp]
	my == "$error"   
    
    matchReport(dp)
}

# Errors to be reported when out of range
report[dp] {
	my := data.target[dp]
	my != "$error"   
    
    matchReport(dp)

    range := get_range(dp)
	not in_range(my, range[0], range[1])
}


all_errors[dp] {
	my := data.target[dp]
    my == "$error"     
}

all_errors[dp] {
	my := data.target[dp]
    my != "$error"
    
    range := get_range(dp)

	not in_range(my, range[0], range[1])
}

in_range(num, low, high) {
	num >= low
    num <= high
}

get_range(dp) = range {
	some key
    range := input.range[key]
    
    glob.match(key, ["_"], dp)
}

matchSkip(dp) {
    some i
    input.skip[i]
    glob.match(input.skip[i], ["_"], dp)
}

matchReport(dp) {
    some i
    input.report[i]
    glob.match(input.report[i], ["_"], dp)
}