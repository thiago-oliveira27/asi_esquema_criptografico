"""
Módulo de Testes para Esquema Criptográfico

Este módulo implementa suite completa de testes para avaliar qualidade
do esquema criptográfico implementado em crypto_scheme.py.

Testes implementados:
1. Correção: Verifica se DEC(K, ENC(K, M)) = M
2. Desempenho: Mede tempo de execução de GEN, ENC, DEC
3. Difusão: Avalia efeito avalanche (mudança de 1 bit em M)
4. Confusão: Avalia impacto de mudança de 1 bit na seed
5. Chaves Equivalentes: Detecta colisões
"""

import random
import time
from typing import Dict, List, Tuple
from crypto_scheme import CryptoScheme


class TestRunner:
    """
    Classe para executar e coletar resultados de testes do esquema criptográfico.
    """
    
    def __init__(self, crypto_scheme: CryptoScheme):
        """
        Inicializa o runner de testes.
        
        Args:
            crypto_scheme: Instância de CryptoScheme a ser testada
        """
        self.crypto = crypto_scheme
    
    def test_correctness(self, seed_size: int, iterations: int = 1000) -> Dict:
        """
        Testa correção: verifica se DEC(K, ENC(K, M)) = M
        
        Args:
            seed_size: Tamanho da seed em bits
            iterations: Número de testes a executar
            
        Returns:
            Dict com resultados: {
                'tests_passed': int,
                'tests_failed': int,
                'success_rate': float
            }
        """
        passed = 0
        failed = 0
        
        for _ in range(iterations):
            # Gerar dados aleatórios
            seed = self._generate_random_bits(seed_size)
            key = self.crypto.GEN(seed)
            message = self._generate_random_bits(len(key))
            
            # Criptografar e descriptografar
            cipher = self.crypto.ENC(key, message)
            decrypted = self.crypto.DEC(key, cipher)
            
            # Verificar correção
            if message == decrypted:
                passed += 1
            else:
                failed += 1
        
        return {
            'tests_passed': passed,
            'tests_failed': failed,
            'success_rate': (passed / iterations) * 100.0
        }
    
    def test_performance(self, seed_size: int, iterations: int = 3000) -> Dict:
        """
        Mede tempo de execução das funções GEN, ENC, DEC.
        
        Args:
            seed_size: Tamanho da seed em bits
            iterations: Número de iterações para medição
            
        Returns:
            Dict com métricas de tempo em milliseconds: {
                'gen_time_ms': float (média),
                'enc_time_ms': float (média),
                'dec_time_ms': float (média),
                'gen_std': float,
                'enc_std': float,
                'dec_std': float,
                'gen_min': float,
                'gen_max': float,
                'enc_min': float,
                'enc_max': float,
                'dec_min': float,
                'dec_max': float
            }
        """
        gen_times = []
        enc_times = []
        dec_times = []
        
        for _ in range(iterations):
            seed = self._generate_random_bits(seed_size)
            message = self._generate_random_bits(4 * seed_size)
            
            # Medir GEN
            start = time.perf_counter()
            key = self.crypto.GEN(seed)
            gen_times.append((time.perf_counter() - start) * 1000)
            
            # Medir ENC
            start = time.perf_counter()
            cipher = self.crypto.ENC(key, message)
            enc_times.append((time.perf_counter() - start) * 1000)
            
            # Medir DEC
            start = time.perf_counter()
            decrypted = self.crypto.DEC(key, cipher)
            dec_times.append((time.perf_counter() - start) * 1000)
        
        return {
            'gen_time_ms': self._mean(gen_times),
            'enc_time_ms': self._mean(enc_times),
            'dec_time_ms': self._mean(dec_times),
            'gen_std': self._std(gen_times),
            'enc_std': self._std(enc_times),
            'dec_std': self._std(dec_times),
            'gen_min': min(gen_times),
            'gen_max': max(gen_times),
            'enc_min': min(enc_times),
            'enc_max': max(enc_times),
            'dec_min': min(dec_times),
            'dec_max': max(dec_times),
            'total_time_ms': self._mean(gen_times) + self._mean(enc_times) + self._mean(dec_times)
        }
    
    def test_diffusion(self, seed_size: int, num_tests: int = 100) -> Dict:
        """
        Testa efeito avalanche (difusão): mudança de 1 bit em M deve afetar ~50% dos bits de C.
        
        Args:
            seed_size: Tamanho da seed em bits
            num_tests: Número de testes a executar
            
        Returns:
            Dict com métricas: {
                'mean_bits_changed': float,
                'percentage': float,
                'min_bits': int,
                'max_bits': int,
                'std_dev': float,
                'distribution': List[int] (contagens por teste)
            }
        """
        bits_changed_counts = []
        key_size = 4 * seed_size
        
        for _ in range(num_tests):
            # Gerar chave e mensagem aleatórias
            seed = self._generate_random_bits(seed_size)
            key = self.crypto.GEN(seed)
            message = self._generate_random_bits(key_size)
            
            # Criptografar mensagem original
            cipher_original = self.crypto.ENC(key, message)
            
            # Para cada bit da mensagem
            bits_changed_per_test = []
            for bit_pos in range(len(message)):
                # Inverter bit
                modified_message = message[:]
                modified_message[bit_pos] = 1 - modified_message[bit_pos]
                
                # Criptografar mensagem modificada
                cipher_modified = self.crypto.ENC(key, modified_message)
                
                # Contar bits diferentes (Hamming distance)
                bits_changed = self._hamming_distance(cipher_original, cipher_modified)
                bits_changed_per_test.append(bits_changed)
            
            # Média de bits alterados para este teste
            avg_bits_changed = self._mean(bits_changed_per_test)
            bits_changed_counts.append(avg_bits_changed)
        
        mean_changed = self._mean(bits_changed_counts)
        percentage = (mean_changed / key_size) * 100.0
        
        return {
            'mean_bits_changed': mean_changed,
            'percentage': percentage,
            'min_bits': min(bits_changed_counts),
            'max_bits': max(bits_changed_counts),
            'std_dev': self._std(bits_changed_counts),
            'distribution': bits_changed_counts,
            'ideal_percentage': 50.0,
            'total_bits': key_size
        }
    
    def test_confusion(self, seed_size: int, num_tests: int = 100) -> Dict:
        """
        Testa confusão: mudança de 1 bit na seed deve afetar significativamente a cifra.
        
        Args:
            seed_size: Tamanho da seed em bits
            num_tests: Número de testes a executar
            
        Returns:
            Dict com métricas: {
                'mean_bits_changed': float,
                'percentage': float,
                'min_bits': int,
                'max_bits': int,
                'std_dev': float,
                'distribution': List[int]
            }
        """
        bits_changed_counts = []
        key_size = 4 * seed_size
        
        for _ in range(num_tests):
            # Gerar seed e mensagem aleatórias
            seed_original = self._generate_random_bits(seed_size)
            message = self._generate_random_bits(key_size)
            
            # Gerar chave e cifrar com seed original
            key_original = self.crypto.GEN(seed_original)
            cipher_original = self.crypto.ENC(key_original, message)
            
            # Para cada bit da seed
            bits_changed_per_test = []
            for bit_pos in range(len(seed_original)):
                # Inverter bit da seed
                modified_seed = seed_original[:]
                modified_seed[bit_pos] = 1 - modified_seed[bit_pos]
                
                # Gerar nova chave e cifrar
                key_modified = self.crypto.GEN(modified_seed)
                cipher_modified = self.crypto.ENC(key_modified, message)
                
                # Contar bits diferentes
                bits_changed = self._hamming_distance(cipher_original, cipher_modified)
                bits_changed_per_test.append(bits_changed)
            
            # Média de bits alterados para este teste
            avg_bits_changed = self._mean(bits_changed_per_test)
            bits_changed_counts.append(avg_bits_changed)
        
        mean_changed = self._mean(bits_changed_counts)
        percentage = (mean_changed / key_size) * 100.0
        
        return {
            'mean_bits_changed': mean_changed,
            'percentage': percentage,
            'min_bits': min(bits_changed_counts),
            'max_bits': max(bits_changed_counts),
            'std_dev': self._std(bits_changed_counts),
            'distribution': bits_changed_counts,
            'target_percentage': 40.0,
            'total_bits': key_size
        }
    
    def test_key_equivalence(self, seed_size: int, num_samples: int = 10000) -> Dict:
        """
        Testa se existem chaves equivalentes (K1 != K2 mas ENC(K1,M) = ENC(K2,M)).
        
        Args:
            seed_size: Tamanho da seed em bits
            num_samples: Número de seeds a gerar
            
        Returns:
            Dict com resultados: {
                'samples_tested': int,
                'equivalent_pairs': int,
                'collision_rate': float
            }
        """
        # Gerar seeds aleatórias
        seeds = []
        for _ in range(num_samples):
            seeds.append(self._generate_random_bits(seed_size))
        
        # Gerar mensagem fixa
        key_size = 4 * seed_size
        message = self._generate_random_bits(key_size)
        
        # Armazenar cifras e suas seeds
        cipher_to_seeds = {}
        collisions = 0
        
        # Testar uma amostra de seeds (não todas - muito custoso)
        sample_size = min(1000, num_samples)
        tested_pairs = 0
        
        for i in range(sample_size):
            seed1 = seeds[i]
            key1 = self.crypto.GEN(seed1)
            cipher1 = self.crypto.ENC(key1, message)
            cipher1_tuple = tuple(cipher1)
            
            # Verificar se já encontramos esta cifra
            if cipher1_tuple in cipher_to_seeds:
                # Verificar se a seed é diferente
                if seeds[cipher_to_seeds[cipher1_tuple]] != seed1:
                    collisions += 1
            else:
                cipher_to_seeds[cipher1_tuple] = i
            
            tested_pairs += 1
        
        collision_rate = (collisions / tested_pairs) * 100.0 if tested_pairs > 0 else 0.0
        
        return {
            'samples_tested': tested_pairs,
            'equivalent_pairs': collisions,
            'collision_rate': collision_rate,
            'total_seeds_generated': num_samples
        }
    
    # ==================== Funções Auxiliares ====================
    
    def _generate_random_bits(self, size: int) -> List[int]:
        """
        Gera lista de bits aleatórios.
        
        Args:
            size: Número de bits a gerar
            
        Returns:
            Lista de 0's e 1's
        """
        return [random.randint(0, 1) for _ in range(size)]
    
    def _hamming_distance(self, bits1: List[int], bits2: List[int]) -> int:
        """
        Calcula distância de Hamming entre duas listas de bits.
        
        Args:
            bits1: Primeira lista de bits
            bits2: Segunda lista de bits
            
        Returns:
            Número de bits diferentes
        """
        if len(bits1) != len(bits2):
            raise ValueError("Listas devem ter mesmo tamanho")
        
        return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
    
    def _mean(self, values: List[float]) -> float:
        """Calcula média de uma lista de valores."""
        if not values:
            return 0.0
        return sum(values) / len(values)
    
    def _std(self, values: List[float]) -> float:
        """
        Calcula desvio padrão de uma lista de valores.
        
        Args:
            values: Lista de valores numéricos
            
        Returns:
            Desvio padrão
        """
        if len(values) < 2:
            return 0.0
        
        mean = self._mean(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5


# Teste básico do módulo
if __name__ == "__main__":
    from crypto_scheme import CryptoScheme
    
    crypto = CryptoScheme()
    runner = TestRunner(crypto)
    
    print("=== Teste de Correção ===")
    result = runner.test_correctness(seed_size=8, iterations=100)
    print(f"Taxa de sucesso: {result['success_rate']:.2f}%")
    print(f"Testes passados: {result['tests_passed']}/{result['tests_passed'] + result['tests_failed']}")
    
    print("\n=== Teste de Desempenho ===")
    result = runner.test_performance(seed_size=8, iterations=100)
    print(f"GEN: {result['gen_time_ms']:.4f} ms (±{result['gen_std']:.4f})")
    print(f"ENC: {result['enc_time_ms']:.4f} ms (±{result['enc_std']:.4f})")
    print(f"DEC: {result['dec_time_ms']:.4f} ms (±{result['dec_std']:.4f})")
