import networkx as nx
import matplotlib.pyplot as plt
import sys
import json
  
path = "network_scan_2023-05-19T10:51:41.000Z.json"
f = open(path)
data = json.load(f)
# Closing file
f.close()
print(data)
# Create a networkx graph object
network_topo = nx.Graph()
labels = {}
for network in data["FOUND_ENTITIES"]["NETWORKS"]:
    for entity in network["ENTITIES"]:
        #print(entity)
        if entity.get("ROUTER"):
            labels[entity["ROUTER"]["ROUTER_MAC"]] = entity["ROUTER"]["ID"]
            network_topo.add_node(entity["ROUTER"]["ROUTER_MAC"])
        else:
            for connection in entity["CONECTED_MAC"]:
                network_topo.add_edge(entity["MAC"], connection)
                labels[entity["MAC"]] = entity["ID"]
            
# Draw the resulting graph
print(labels)
options = {"edgecolors": "tab:gray", "node_size": 800, "alpha": 0.9, "with_labels":True, "font_weight":"bold"}
nx.draw(network_topo, node_color="tab:red", **options)

#nx.draw_networkx_labels(network_topo, labels, font_size=22, font_color="whitesmoke")

ax = plt.gca()
ax.margins(0.3)
plt.axis("off")
plt.show()