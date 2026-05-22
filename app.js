"""
Merkle Tree Implementation for Certificate Verification
"""
import hashlib
from typing import List, Optional

class MerkleNode:
    """Node in the Merkle Tree"""
    def __init__(self, left=None, right=None, data=None, hash_value=None):
        self.left = left
        self.right = right
        self.data = data
        self.hash = hash_value or self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of the node"""
        if self.data:
            return hashlib.sha256(self.data.encode()).hexdigest()
        else:
            left_hash = self.left.hash if self.left else ""
            right_hash = self.right.hash if self.right else ""
            return hashlib.sha256((left_hash + right_hash).encode()).hexdigest()

class MerkleTree:
    """Merkle Tree for batch certificate verification"""
    
    def __init__(self, certificates: List[str]):
        """
        Initialize Merkle Tree with certificate hashes
        Args:
            certificates: List of certificate hashes (already hashed)
        """
        # Use certificate hashes directly as leaf hashes (don't hash again)
        self.leaves = [MerkleNode(hash_value=cert) for cert in certificates]
        self.root = self.build_tree(self.leaves)
    
    def build_tree(self, nodes: List[MerkleNode]) -> Optional[MerkleNode]:
        """
        Build Merkle Tree from leaf nodes
        Args:
            nodes: List of MerkleNode objects
        Returns:
            Root node of the tree
        """
        if not nodes:
            return None
        
        if len(nodes) == 1:
            return nodes[0]
        
        # If odd number of nodes, duplicate the last one
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])
        
        parent_nodes = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            parent = MerkleNode(left=left, right=right)
            parent_nodes.append(parent)
        
        return self.build_tree(parent_nodes)
    
    def get_root_hash(self) -> str:
        """Get the root hash of the Merkle Tree"""
        return self.root.hash if self.root else ""
    
    def get_proof(self, cert_hash: str) -> List[tuple]:
        """
        Generate Merkle proof for a certificate
        Args:
            cert_hash: Certificate hash to verify
        Returns:
            List of (hash, position) tuples for verification path
        """
        proof = []
        
        # Find the leaf node
        leaf_index = None
        for i, leaf in enumerate(self.leaves):
            if leaf.hash == cert_hash:
                leaf_index = i
                break
        
        if leaf_index is None:
            return []
        
        # Build proof path
        nodes = self.leaves[:]
        
        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            
            # Find sibling
            if leaf_index % 2 == 0:
                sibling_index = leaf_index + 1
                position = "right"
            else:
                sibling_index = leaf_index - 1
                position = "left"
            
            if sibling_index < len(nodes):
                proof.append((nodes[sibling_index].hash, position))
            
            # Move to parent level
            leaf_index = leaf_index // 2
            parent_nodes = []
            for i in range(0, len(nodes), 2):
                parent = MerkleNode(left=nodes[i], right=nodes[i + 1])
                parent_nodes.append(parent)
            nodes = parent_nodes
        
        return proof
    
    def verify_proof(self, cert_hash: str, proof: List[tuple], root_hash: str) -> bool:
        """
        Verify a certificate using Merkle proof
        Args:
            cert_hash: Certificate hash to verify
            proof: Merkle proof path
            root_hash: Expected root hash
        Returns:
            True if certificate is valid, False otherwise
        """
        current_hash = cert_hash
        
        # If no proof (single node tree), compare directly
        if len(proof) == 0:
            return current_hash == root_hash
        
        for sibling_hash, position in proof:
            if position == "left":
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == root_hash

def generate_certificate_hash(student_name: str, course: str, grade: str) -> str:
    """
    Generate SHA-256 hash for certificate data
    Args:
        student_name: Student's name
        course: Course name
        grade: Grade received
    Returns:
        SHA-256 hash string
    """
    data = student_name + course + grade
    return hashlib.sha256(data.encode()).hexdigest()
