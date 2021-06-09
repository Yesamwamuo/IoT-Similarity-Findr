import json
import os


class MatchedFunction:
	MATCH_TYPE_VALUE = 'value'
	MATCH_TYPE_CHILD = 'child'
	MATCH_TYPE_NEIGBOUR = 'neighbor'

	def __init__(self, fname, param_size, match_type):
		self.fname = fname
		self.param_size = param_size
		self.match_count = 1
		self.match_type = match_type

	def inc_count(self):
		self.match_count += 1

	def __repr__(self):
		return "{\"name\":\"%s\" \"param_size\":%s \"type\":\"%s\" \"match_count\":%s}" % (self.fname, self.param_size, self.match_type, self.match_count)

	def __str__(self):
		return "{\"name\":\"%s\" \"param_size\":%s \"type\":\"%s\" \"match_count\":%s}" % (self.fname, self.param_size, self.match_type, self.match_count)

# Add by type if new, or just increase match count
def add_match(funcA, funcB, len, match_type):
	if funcA not in matched_funcs:
		matched = MatchedFunction(funcB, len, match_type)
		matched_funcs[funcA] = matched
	else:
		matched = matched_funcs[funcA]
		matched.inc_count()
		matched_funcs[funcA] = matched


# Functions must be of the same signature length, and checks min signature length
def match_by_param_length(a, b):
	return len(a) == len(b) and len(a) >= MIN_SIGNT_LENGTH

# Params must match one to one and checks min immediate value count
def match_by_value(a, b):
	count = 0
	for i in range(1, len(a)):
		if a[i] != b[i]:
			return False
		else:
			# if a value is null or a number
			if not a[i] or a[i].isnumeric():
				count += 1

	return count >= MIN_VALUE_MATCH_COUNT


def match(a, b):
	return match_by_param_length(a, b) and match_by_value(a, b)


matched_funcs = {}
MIN_VALUE_MATCH_COUNT = 2
MIN_SIGNT_LENGTH = 3
MIN_NEIGHBOR_MATCH_THRESH = 0.7
folder = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(folder, '20140210204804.kml')
graphA = json.loads(
	open(os.path.join(folder, 'current_firmware.json'), 'r').read())
graphB = json.loads(
	open(os.path.join(folder, 'update_firmware.json'), 'r').read())


'''
STEP 1: Match called functions with at least n similar immediate value with the same Length
'''
calledListA = [called for func in graphA for called in graphA[func]]
calledListB = [called for func in graphB for called in graphB[func]]

for func1 in calledListA:
	for func2 in list(calledListB):
		if match(func1, func2):
			add_match(func1[0], func2[0], len(func2) - 1,
					  MatchedFunction.MATCH_TYPE_VALUE)
			calledListB.remove(func2)

print('Step one, Found:', len(matched_funcs))


'''
STEP2
STEP 2.1: Check matched functions have same number of called functions 
Step 2.2: Match Called functions of matched functions
'''
def step2():
	for funcA in list(matched_funcs.keys()):
		funcB = matched_funcs[funcA].fname
		calledFuncsA = graphA[funcA]
		calledFuncsB = graphB[funcB]
		'''Functions with the same signature but different number of called functions 
		may indicate an update, remove for now because they are different '''
		if len(calledFuncsA) != len(calledFuncsB):
			print("Do not match, Updated?", funcA, funcB)
			matched_funcs.pop(funcA)
			continue

		'''Called Functions with different different call sequence or signature length 
		may indicate an update, remove for now because they are different '''
		for i in range(len(calledFuncsB)):
			if len(calledFuncsA[i]) != len(calledFuncsB[i]):
				print("Do not match 2, Updated?", funcA, funcB)
				matched_funcs.pop(funcA)
				break
	# 2.2 Add called functions of matched functions
	for funcA in list(matched_funcs.keys()):
		funcB = matched_funcs[funcA].fname
		calledFuncsA = graphA[funcA]
		calledFuncsB = graphB[funcB]
		for i in range(len(calledFuncsB)):
			add_match(calledFuncsA[i][0], calledFuncsB[i][0], len(
				calledFuncsB[i]) - 1, MatchedFunction.MATCH_TYPE_CHILD)

#Perform Step 2 Until there is no new called function to match
old_len = len(matched_funcs)
while True:
	step2()
	print('New Length', len(matched_funcs))

	if old_len == len(matched_funcs):
		break
	else:
		old_len = len(matched_funcs)

print('Step Two, Found:', len(matched_funcs))


'''
STEP3
Populate Neigbours, Neighbours = called functions(child/callee) + callers(parents)
If functions have similar Neighbors above MIN_NEIGHBOR_MATCH_THRESH they probably match
'''
graphA_neighbors = {}
graphB_neighbors = {}
for vert1 in graphA:
	graphA_neighbors[vert1] = [func[0] for func in graphA[vert1]]
	for vert2 in graphA:
		if vert1 in [func[0] for func in graphA[vert2]]:
			graphA_neighbors[vert1].append(vert2)

for vert1 in graphB:
	graphB_neighbors[vert1] = [func[0] for func in graphB[vert1]]
	for vert2 in graphB:
		if vert1 in [func[0] for func in graphB[vert2]]:
			graphB_neighbors[vert1].append(vert2)

for vert1 in graphA:
	for vert2 in graphB:
		neighborpairs = 0
		for vert3 in graphA_neighbors[vert1]:
			for vert4 in graphB_neighbors[vert2]:
				if vert3 in matched_funcs.keys() and matched_funcs[vert3].fname == vert4:
					neighborpairs += 1
		try:
			if neighborpairs/max(len(graphA_neighbors[vert1]), len(graphB_neighbors[vert2])) > MIN_NEIGHBOR_MATCH_THRESH:
				add_match(vert1, vert2, 0, MatchedFunction.MATCH_TYPE_NEIGBOUR)
		except:
			pass

matched_len = len(matched_funcs)
print('Step Three, Found:', matched_len)

print(len(graphA))
	
print("Could not match %s of %s in graphA" % (len(graphA) - matched_len,len(graphA)))
print("Could not match %s of %s in graphB" % (len(graphB) - matched_len,len(graphB)))
print('')
print(matched_funcs)