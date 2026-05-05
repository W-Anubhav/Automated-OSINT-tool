import networkx as nx
from pyvis.network import Network
import tempfile
import os

class GraphManager:
    def __init__(self):
        self.G = nx.MultiDiGraph()

    def add_target_node(self, target):
        self.G.add_node(target, label=target, type="Target", color="#ff4b4b", size=30)

    def add_osint_data(self, target, data):
        """
        Connects OSINT findings to the target.
        """
        # Hunter.io emails
        if "data" in data and "emails" in data["data"]:
            for email_info in data["data"]["emails"]:
                email = email_info.get("value")
                self.G.add_node(email, label=email, type="Email", color="#1c83e1", size=20)
                self.G.add_edge(target, email, relationship="Found Email")

        # DNS Records
        if "A" in data:
            for ip in data["A"]:
                self.G.add_node(ip, label=ip, type="IP", color="#00d4ff", size=25)
                self.G.add_edge(target, ip, relationship="Resolves to")

    def add_breach_data(self, email, breach_data):
        """
        Connects breach findings to an email.
        """
        if not breach_data or "error" in breach_data:
            return

        # BreachDirectory returns a list of results
        if isinstance(breach_data, list):
            for result in breach_data:
                source = result.get("source", "Unknown Breach")
                leak_label = f"Leak: {source}"
                self.G.add_node(leak_label, label=leak_label, type="Breach", color="#f5a623", size=15)
                self.G.add_edge(email, leak_label, relationship="Involved in Breach")

    def add_scan_results(self, ip, scan_results):
        """
        Connects open ports and services to an IP.
        """
        for host_info in scan_results:
            if host_info["host"] == ip:
                for proto_data in host_info["protocols"]:
                    for port_info in proto_data["ports"]:
                        port_label = f"Port {port_info['port']} ({port_info['service']})"
                        self.G.add_node(port_label, label=port_label, type="Port", color="#2edb8b", size=15)
                        self.G.add_edge(ip, port_label, relationship="Open Port")
                        
                        if port_info.get("version"):
                            version_label = f"{port_info['product']} {port_info['version']}"
                            self.G.add_node(version_label, label=version_label, type="Version", color="#ffd166", size=10)
                            self.G.add_edge(port_label, version_label, relationship="Service Version")

    def generate_interactive_graph(self):
        net = Network(height="600px", width="100%", bgcolor="#0e1117", font_color="white", notebook=False, directed=True)
        
        # Add nodes and edges from NetworkX graph
        for node, attrs in self.G.nodes(data=True):
            net.add_node(node, label=attrs.get('label', node), color=attrs.get('color'), size=attrs.get('size'))
        
        for source, target, attrs in self.G.edges(data=True):
            net.add_edge(source, target, title=attrs.get('relationship'))

        # Set physics for better visualization
        net.set_options("""
        var options = {
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -50,
              "centralGravity": 0.01,
              "springLength": 100,
              "springConstant": 0.08
            },
            "maxVelocity": 50,
            "solver": "forceAtlas2Based",
            "timestep": 0.35,
            "stabilization": { "iterations": 150 }
          }
        }
        """)
        
        # Save to temporary file
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmp_file.name)
        return tmp_file.name
