class Agent():
    def __init__(self, name, agent_type, traits, children):
        self.name = name
        self.agent_type = agent_type
        self.traits = traits
        self.children = children

    def __str__(self):
        return f"Agent(name={self.name}, agent_type={self.agent_type}, traits={self.traits}, children={self.children})"

    def __repr__(self):
        return self.__str__()