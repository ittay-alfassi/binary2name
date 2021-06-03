class Vertex:
    def __init__(self, baddr: int):
        self.baddr = baddr
    
    def __eq__(self, other):
        assert(isinstance(other, Vertex))
        return self.baddr == other.baddr

class Edge:
    def __init__(self, source: Vertex, dest: Vertex, constraint: list):
        self.constraint = constraint
        self.source = source
        self.dest = dest

    def __eq__(self, other):
        assert(isinstance(other, Edge))
        return (self.source == other.source and self.dest == other.dest)
        


class SymGraph:
    def __init__(self, root: Vertex):
        self.root = root
        self.vertices = {}
        self.addVertex(root)

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
