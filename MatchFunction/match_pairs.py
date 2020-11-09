import json

'''
TODO: when on the same, should give a value of 1.0, not 2.0???????????????
TODO: make step 3 try to be bottom-up rather than spidering weirdly'''

xiaomi_graph = json.loads(open('xiaomi.json', 'r').read())
wyze_graph = json.loads(open('wyze.json', 'r').read())
categories = json.loads(open('categories.json', 'r').read())
matched_vertices = {}
atomic_subcategories = dict()  # STEP 1
atomic_vertices = []
for vert1 in xiaomi_graph:
	if vert1 in wyze_graph and not len(xiaomi_graph[vert1]) and not len(wyze_graph[vert1]):
		atomic_vertices.append(vert1)
		matched_vertices[vert1] = vert1
		# xiaomi_graph.pop(vert1)
		# wyze_graph.pop(vert1)

for vert in atomic_vertices:
	xiaomi_graph.pop(vert)
	wyze_graph.pop(vert)  
    
# STEP 1.5
for func in wyze_graph:
	atomic_subcategories[func] = set()
for func in xiaomi_graph:
	atomic_subcategories[func] = set()
for vert in atomic_vertices:
	for func in wyze_graph:
		if vert in wyze_graph[func]:
			for category in categories:
				if vert in categories[category]:
					atomic_subcategories[func].add(category)
	for func in xiaomi_graph:
		if vert in xiaomi_graph[func]:
			for category in categories:
				if vert in categories[category]:
					atomic_subcategories[func].add(category)


def get_atomic_funcs(func_name, graph, been_seen):
	for subfunc in graph[func_name]:
		print(been_seen)
		if subfunc in been_seen:
			continue
		been_seen.append(func_name)
		atomic_subcategories[func_name].update(
		    get_atomic_funcs(subfunc, graph, been_seen))
	return atomic_subcategories[func_name]

for func in wyze_graph:
    try:
        print('top')
        seen_array = []
        atomic_subcategories.update(get_atomic_funcs(func, wyze_graph, seen_array))
    except KeyError:
        pass
for func in xiaomi_graph:
	try:
		seen_array = []
		atomic_subcategories.update(get_atomic_funcs(func, xiaomi_graph, seen_array))
	except KeyError:
		pass
print(atomic_subcategories)

# STEP 2
for vert1 in xiaomi_graph:
	vert1_atomics = set()
	for callee1 in xiaomi_graph[vert1]:
		if callee1 in atomic_vertices:
			vert1_atomics.add(callee1)
	for vert2 in wyze_graph:
		vert2_atomics = set()
		for callee2 in wyze_graph[vert2]:
			if callee2 in atomic_vertices:
				vert2_atomics.add(callee2)
		if vert1_atomics == vert2_atomics and len(vert1_atomics) > 1:
			matched_vertices[vert1] =  vert2
			# xiaomi_graph.pop(vert1)
			# wyze_graph.pop(vert2)
            
 # STEP 3
xiaomi_graph_neighbors = {}
wyze_graph_neighbors = {}
for vert1 in xiaomi_graph:
	xiaomi_graph_neighbors[vert1] = xiaomi_graph[vert1]
	for vert2 in xiaomi_graph:
		if vert1 in xiaomi_graph[vert2]:
			xiaomi_graph_neighbors[vert1].append(vert2)
for vert1 in wyze_graph:
	wyze_graph_neighbors[vert1] = wyze_graph[vert1]
	for vert2 in wyze_graph:
		if vert1 in wyze_graph[vert2]:
			wyze_graph_neighbors[vert1].append(vert2)

for vert1 in xiaomi_graph:
	for vert2 in wyze_graph:
		neighborpairs = 0
		for vert3 in xiaomi_graph_neighbors[vert1]:
			for vert4 in wyze_graph_neighbors[vert2]:
				if vert3 in matched_vertices.keys() and matched_vertices[vert3] == vert4:
					neighborpairs += 1
		try:
			if neighborpairs/max(len(xiaomi_graph_neighbors[vert1]), len(wyze_graph_neighbors[vert2])) > 0.7:
				matched_vertices[vert1] =  vert2
				# print(f"added pair {vert1}, {vert2}!")
		except:
			pass
			# print(vert1, vert2, xiaomi_graph[vert1], wyze_graph[vert2])print(xiaomi_graph.keys())
print(matched_vertices)
# print(len(matched_vertices)/max(len(xiaomi_graph), len(wyze_graph)))
