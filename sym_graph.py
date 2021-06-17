

class Vertex:
    def __init__(self, baddr: int, instructions: str, constraint: str = ""):
        self.baddr = baddr
        self.instructions = instructions
        self.constraint = constraint
    
    # we define uniqueness by address only
    def __eq__(self, other):
        assert(isinstance(other, Vertex))
        return self.baddr == other.baddr

    # defined for using Vertex as dict key
    def __hash__(self):
        return hash(self.baddr)

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

        


class SymGraph:
    def __init__(self, root: Vertex, func_name: str="fun"):
        self.root = root
        self.vertices = {}
        self.addVertex(root)
        self.func_name = func_name

    def __find_vertex(self, vertex: Vertex) -> Vertex:
        duplicates = [v for v in self.vertices.keys() if v.baddr == vertex.baddr]
        if duplicates == []:
            return None
        assert(len(duplicates) == 1)
        return duplicates[0]

    def addVertex(self, vertex: Vertex):
        if vertex.baddr in self.vertices.keys():
            vertex.constraint += (' <<OR>> ' + self.vertices[vertex.baddr].constraint)
        
        self.vertices[vertex.baddr] = vertex

#TODO: change edge def to ints!
    def addEdge(self, edge: Edge):
        if (not(edge.source in self.vertices.keys())):
            self.addVertex(edge.source)
        if (not(edge.dest in self.vertices.keys())):
            self.addVertex(edge.dest)

        if (not(edge in self.vertices[edge.source])):
            self.vertices[edge.source].append(edge)

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

        
