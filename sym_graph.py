class Vertex:
    def __init__(self, baddr: int, instructions: str):
        self.baddr = baddr
        self.instructions = instructions
    
    # we define uniqueness by address only
    def __eq__(self, other):
        assert(isinstance(other, Vertex))
        return self.baddr == other.baddr

    # defined for using Vertex as dict key
    def __hash__(self):
        return hash(self.baddr)

    def __str__(self):
        return f'"{self.baddr}": "{self.instructions}"'

class Edge:
    def __init__(self, source: Vertex, dest: Vertex, constraint: str):
        self.constraint = constraint
        self.source = source
        self.dest = dest

    def __eq__(self, other):
        assert(isinstance(other, Edge))
        return (self.source == other.source and self.dest == other.dest)

    def __str__(self):
        return f'{{"EDGE": ["{self.source.baddr}", "{self.dest.baddr}"],   "CONSTRAINT": "{self.constraint}"}}'

        


class SymGraph:
    def __init__(self, root: Vertex, func_name: str="fun"):
        self.root = root
        self.vertices = {}
        self.addVertex(root)
        self.func_name = func_name

    def addVertex(self, vertex: Vertex):
        if (not(vertex in self.vertices.keys())):
            self.vertices[vertex] = []

    def addEdge(self, edge: Edge):
        if (not(edge.source in self.vertices.keys())):
            self.addVertex(edge.source)
        if (not(edge.dest in self.vertices.keys())):
            self.addVertex(edge.dest)

        if (not(edge in self.vertices[edge.source])):
            self.vertices[edge.source].append(edge)

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

        
