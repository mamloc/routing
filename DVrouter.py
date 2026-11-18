
####################################################
# DVrouter.py
# Project 2 - Distance Vector Routing
####################################################

import json

from router import Router
from packet import Packet


class DVrouter(Router):

    INFINITY = 16

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.adjacent_nodes = {} # (địa chỉ điểm cuối, chi phí kết nối)

        self.received_tables = {} # các khoảng cách được quảng bá từ láng giềng đó

        self.best_costs = {self.addr: 0} # điểm đến -> khoảng cách ngắn nhất đã biết

        self.next_hops = {} # đích -> cổng chuyển tiếp

    def refresh_paths(self):
        """Build the routing table using Bellman-Ford."""

        updated_costs = {self.addr: 0}
        updated_ports = {}

        for port_id, link_info in self.adjacent_nodes.items():
            neighbor_addr, edge_weight = link_info

            if edge_weight < updated_costs.get(
                neighbor_addr, self.INFINITY
            ):
                updated_costs[neighbor_addr] = edge_weight
                updated_ports[neighbor_addr] = port_id

            advertised = self.received_tables.get(port_id, {})

            for target, advertised_cost in advertised.items():

                if target == self.addr:
                    continue

                if advertised_cost >= self.INFINITY:
                    continue

                candidate_cost = edge_weight + advertised_cost

                if candidate_cost >= self.INFINITY:
                    continue

                previous_cost = updated_costs.get(
                    target, self.INFINITY
                )

                if candidate_cost < previous_cost:
                    updated_costs[target] = candidate_cost
                    updated_ports[target] = port_id

        has_changed = (
            updated_costs != self.best_costs
            or updated_ports != self.next_hops
        )

        self.best_costs = updated_costs
        self.next_hops = updated_ports

        return has_changed

    def announce_routes(self):
        """Advertise the current vector to adjacent nodes."""

        for port_id, link_info in self.adjacent_nodes.items():
            neighbor_addr, _ = link_info

            outgoing_vector = {}

            for target, known_cost in self.best_costs.items():
                if (
                    target != neighbor_addr
                    and self.next_hops.get(target) == port_id
                ):
                    outgoing_vector[target] = self.INFINITY
                else:
                    outgoing_vector[target] = known_cost

            message = Packet(
                Packet.ROUTING,
                self.addr,
                neighbor_addr,
                json.dumps(outgoing_vector)
            )

            self.send(port_id, message)

    def handle_packet(self, port, packet):
        """Process incoming data and routing packets."""

        if packet.is_traceroute:

            target = packet.dst_addr
            selected_port = self.next_hops.get(target)

            if selected_port is not None:
                self.send(selected_port, packet)

            return

        if not packet.is_routing:
            return

        if port not in self.adjacent_nodes:
            return

        neighbor_addr, _ = self.adjacent_nodes[port]

        if packet.src_addr != neighbor_addr:
            return

        try:
            incoming_vector = json.loads(packet.content)
        except (ValueError, TypeError):
            return

        if not isinstance(incoming_vector, dict):
            return
        
        for value in incoming_vector.values():
            if (
                type(value) not in (int, float)
                or value < 0
            ):
                return

        if incoming_vector == self.received_tables.get(port):
            return

        self.received_tables[port] = incoming_vector

        if self.refresh_paths():
            self.announce_routes()

    def handle_new_link(self, port, endpoint, cost):
        """Register a new link or an updated connection."""

        self.adjacent_nodes[port] = (endpoint, cost)
        self.received_tables.pop(port, None)

        self.refresh_paths()
        self.announce_routes()

    def handle_remove_link(self, port):
        """Remove a link and calculate alternative routes."""

        if port not in self.adjacent_nodes:
            return

        del self.adjacent_nodes[port]
        self.received_tables.pop(port, None)

        self.refresh_paths()
        self.announce_routes()

    def handle_time(self, time_ms):
        """Send periodic distance-vector updates."""

        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.announce_routes()

    def __repr__(self):
        """Display router information for debugging."""

        return (
            f"DVrouter: {self.addr}\n"
            f"Connected: {self.adjacent_nodes}\n"
            f"Distances: {self.best_costs}\n"
            f"Forwarding: {self.next_hops}"
        )
