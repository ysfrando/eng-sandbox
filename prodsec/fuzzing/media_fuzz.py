import os
import sys
import random
import subprocess
import signal
import time
from multiprocessing import Pool
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("fuzz_results.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MediaFuzzer:
    def __init__(self, target_binary, corpus_dir, output_dir, timeout=10):
        self.target_binary = target_binary
        self.corpus_dir = Path(corpus_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(exist_ok=True)
        self.timeout = timeout
        self.mutation_count = 1000
        self.max_iterations = 10000

        # Ensure target exists:
        if not os.path.isfile(target_binary):
            raise FileNotFoundError(f"Target binary not found: {target_binary}")
        
        # Ensure corpus directory exists and has files
        if not self.corpus_dir.is_dir():
            raise FileNotFoundError(f"Corpus directory not found: {corpus_dir}")
        
        self.corpus_files = list(self.corpus_dir.glob("*")) # Retrieve all files with *
        if not self.corpus_files:
            raise FileNotFoundError(f"No files found in corpus directory: {corpus_dir}")
        
        logger.info(f"Initialized fuzzer with {len(self.corpus_files)} corpus files")

    def mutate_file(self, input_file):
        """Create a mutated version of the input file"""
        with open(input_file, 'rb') as f:
            content = bytearray(f.read())
            
            if not content:
                return None
            
            # Apply random mutations
            mutations = random.randint(1, 10)
            for _ in range(mutations):
                mutation_type = random.randint(1, 4)
                
                if mutation_type == 1 and len(content) > 0:
                    # Bit flip
                    pos = random.randint(0, len(content) - 1)
                    bit = random.randint(0, 7)
                    content[pos] ^= (1 << bit)
                    
                elif mutation_type == 2 and len(content) > 1:
                    # Byte swap
                    pos1 = random.randint(0, len(content) - 1)
                    pos2 = random.randint(0, len(content) - 1)
                    content[pos1], content[pos2] = content[pos2], content[pos1]
                    
                elif mutation_type == 3 and len(content) > 0:
                    # Insert byte
                    pos = random.randint(0, len(content))
                    content.insert(pos, random.random(0, 255))
                    
                elif mutation_type == 4 and len(content) > 10:
                    # Delete byte
                    pos = random.randint(0, len(content) - 1)
                    del content[pos]
                    
            # Create mutated file
            output_path = self.output_dir / f"mutated_{hash(bytes(content))}.bin"
            with open(output_path, 'wb') as f:
                f.write(content)
                
            return output_path
