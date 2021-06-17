

class Vertex:
    def __init__(self, baddr: int, instructions: str, constraint = []):
        self.baddr = baddr
        self.instructions = instructions
        self.constraint = constraint
    
    # we define uniqueness by address only
    def __eq__(self, other):
        assert(isinstance(other, Vertex))
        return self.baddr == other.baddr

    def __str__(self):
        return f'"{self.baddr}": "{self.instructions}", CONSTRAINT: "{self.constraint}"'

class Edge:
    def __init__(self, source: int, dest: int):
        self.source = source
        self.dest = dest

    def __eq__(self, other):
        assert(isinstance(other, Edge))
        return (self.source == other.source and self.dest == other.dest)

    def __str__(self):
        return f'{{"EDGE": ["{self.source}", "{self.dest}"]"}}'

        


class SymGraph: # TODO: sanity check, when graph is done, vertices.keys() length is same as edges.keys()
    def __init__(self, root: Vertex, func_name: str="unknown_function"):
        self.root = root
        self.vertices = {} # a dictionary from bbl_addr to Vertex item
        self.edges = {} # a dictionary from bbl_addr to all bbl_addr that has an edge between them
        self.addVertex(root)
        self.func_name = func_name

    def __find_vertex(self, vertex: Vertex) -> Vertex:
        duplicates = [v for v in self.vertices.keys() if v == vertex]
        if duplicates == []:
            return None
        assert(len(duplicates) == 1)
        return duplicates[0]

    def addVertex(self, vertex: Vertex):
        if vertex in self.vertices:
            vertex.constraint += self.vertices[vertex.baddr].constraint
        
        self.vertices[vertex.baddr] = vertex

    def addEdge(self, edge: Edge):
        if (edge.source not in self.edges.keys()):
            self.edges[edge.source] = []
        if (edge.dest not in self.edges.keys()):
            self.edges[edge.dest] = []

        if (edge.dest not in self.edges[edge.source]):
            self.edges[edge.source].append(edge.dest)

    #TODO: redo the printing!
    def __str__(self):
        res = f'{{ "func_name": "{self.func_name}",'
        res += f'"GNN_DATA": {{'
        res += f'"nodes": {{'
        res += ', '.join([str(v) for v in self.vertices.keys()])

        res += f'}}, "edges": ['
        all_edges = [item for sublist in self.vertices.values() for item in sublist]
        res += ', '.join([str(e) for e in all_edges])
        
        res += f'] }} }}'
        return res

        
