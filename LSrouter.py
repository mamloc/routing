
####################################################
# LSrouter.py
# Project 2 - Link State Routing
####################################################

import json
import heapq

from router import Router
from packet import Packet


class LSrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.local_links = {}

        self.topology_records = {
            self.addr: (0, {})
        }

        self.current_seq = 0

        self.route_ports = {}

        self.path_costs = {self.addr: 0}

    def publish_state(self):
        """Advertise a new version of this router's links."""

        self.current_seq += 1

        link_map = {
            endpoint: weight
            for endpoint, weight in self.local_links.values()
        }

        self.topology_records[self.addr] = (
            self.current_seq,
            link_map
        )

        self.update_shortest_paths()

        self.flood_state(
            self.addr,
            self.current_seq,
            link_map
        )

    def flood_state(self, origin, sequence, links,
                    excluded_port=None):
        """Forward a link-state advertisement."""

        message_data = json.dumps({
            "origin": origin,
            "seq": sequence,
            "links": links
        })

        for port_id, (peer, _) in self.local_links.items():

            if port_id == excluded_port:
                continue

            lsa_packet = Packet(
                Packet.ROUTING,
                self.addr,
                peer,
                message_data
            )

            self.send(port_id, lsa_packet)

    def sync_database(self, port):
        """Share known LSAs with a newly connected node."""

        if port not in self.local_links:
            return

        peer, _ = self.local_links[port]

        for origin, record in self.topology_records.items():
            sequence, links = record

            payload = json.dumps({
                "origin": origin,
                "seq": sequence,
                "links": links
            })

            packet = Packet(
                Packet.ROUTING,
                self.addr,
                peer,
                payload
            )

            self.send(port, packet)

    def update_shortest_paths(self):
        """Compute minimum-cost paths using Dijkstra."""

        graph = {}

        for origin, (_, links) in self.topology_records.items():
            graph[origin] = dict(links)

        graph[self.addr] = {
            endpoint: cost
            for endpoint, cost in self.local_links.values()
        }

        distances = {self.addr: 0}
        first_ports = {}

        pending = [(0, self.addr)]

        while pending:
            current_cost, current_node = heapq.heappop(
                pending
            )

            if current_cost != distances.get(current_node):
                continue

            for destination, weight in graph.get(
                current_node, {}
            ).items():

                candidate = current_cost + weight

                if candidate >= distances.get(
                    destination, float("inf")
                ):
                    continue

                if current_node == self.addr:

                    outgoing_port = None

                    for port_id, (peer, _) in (
                        self.local_links.items()
                    ):
                        if peer == destination:
                            outgoing_port = port_id
                            break
                else:
                    outgoing_port = first_ports.get(
                        current_node
                    )

                if outgoing_port is None:
                    continue

                distances[destination] = candidate
                first_ports[destination] = outgoing_port

                heapq.heappush(
                    pending,
                    (candidate, destination)
                )

        self.path_costs = distances
        self.route_ports = first_ports

    def handle_packet(self, port, packet):
        """Handle traceroute packets and incoming LSAs."""

        if packet.is_traceroute:

            destination = packet.dst_addr
            outgoing_port = self.route_ports.get(
                destination
            )

            if outgoing_port is not None:
                self.send(outgoing_port, packet)

            return

        if not packet.is_routing:
            return

        if port not in self.local_links:
            return

        try:
            received_data = json.loads(packet.content)

            origin = received_data["origin"]
            sequence = received_data["seq"]
            links = received_data["links"]

        except (ValueError, TypeError, KeyError):
            return

        if not isinstance(links, dict):
            return

        if not isinstance(sequence, int):
            return

        if origin == self.addr:
            return

        previous = self.topology_records.get(origin)

        if previous is not None:
            old_seq, _ = previous

            if sequence <= old_seq:
                return

        self.topology_records[origin] = (
            sequence,
            links
        )

        self.update_shortest_paths()

        self.flood_state(
            origin,
            sequence,
            links,
            excluded_port=port
        )

    def handle_new_link(self, port, endpoint, cost):
        """Update local links after a new connection."""

        self.local_links[port] = (endpoint, cost)

        self.publish_state()

        self.sync_database(port)

    def handle_remove_link(self, port):
        """Update topology after a disconnected link."""

        if port not in self.local_links:
            return

        del self.local_links[port]

        self.publish_state()

    def handle_time(self, time_ms):
        """Periodically refresh our own advertisement."""

        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.publish_state()

    def __repr__(self):
        """Display useful information during debugging."""

        return (
            f"LSrouter(addr={self.addr})\n"
            f"Links: {self.local_links}\n"
            f"Sequence: {self.current_seq}\n"
            f"Topology: {self.topology_records}\n"
            f"Costs: {self.path_costs}\n"
            f"Forwarding: {self.route_ports}"
        )
