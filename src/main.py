"""
Script Principal - Esquema Criptográfico Simplificado

Este script executa todos os testes do esquema criptográfico e gera
relatórios detalhados em formato JSON e texto.

Uso:
    python main.py
"""

import json
import sys
from datetime import datetime
from typing import Dict
from crypto_scheme import CryptoScheme
from tests import TestRunner


def main():
    """
    Função principal que executa todos os testes e gera relatórios.
    """
    print("=" * 60)
    print("ESQUEMA CRIPTOGRÁFICO SIMPLIFICADO")
    print("Trabalho de Auditoria e Segurança da Informação")
    print("=" * 60)
    print()
    
    # Inicializar componentes
    crypto = CryptoScheme()
    runner = TestRunner(crypto)
    
    # Definir tamanhos de seed a testar
    # seed_sizes = [8, 16, 32, 64, 128]
    seed_sizes = [8, 16, 32, 64]
    
    # Estrutura para armazenar todos os resultados
    all_results = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'python_version': sys.version,
            'seed_sizes_tested': seed_sizes
        },
        'correctness': {},
        'performance': {},
        'diffusion': {},
        'confusion': {},
        'key_equivalence': {}
    }
    
    # Executar testes para cada tamanho de seed
    for seed_size in seed_sizes:
        print(f"\n{'='*60}")
        print(f"Testando com seed_size = {seed_size} bits (key_size = {4*seed_size} bits)")
        print(f"{'='*60}")
        
        # 1. Teste de Correção
        print("\n[1/5] Executando teste de correção...")
        correctness = runner.test_correctness(seed_size, iterations=1000)
        all_results['correctness'][f'seed_{seed_size}'] = correctness
        print(f"✓ Taxa de sucesso: {correctness['success_rate']:.2f}%")
        
        # 2. Teste de Desempenho
        print("\n[2/5] Executando teste de desempenho...")
        performance = runner.test_performance(seed_size, iterations=1000)
        all_results['performance'][f'seed_{seed_size}'] = performance
        print(f"✓ GEN: {performance['gen_time_ms']:.4f} ms")
        print(f"✓ ENC: {performance['enc_time_ms']:.4f} ms")
        print(f"✓ DEC: {performance['dec_time_ms']:.4f} ms")
        
        # 3. Teste de Difusão
        print("\n[3/5] Executando teste de difusão...")
        diffusion = runner.test_diffusion(seed_size, num_tests=100)
        all_results['diffusion'][f'seed_{seed_size}'] = diffusion
        print(f"✓ Bits alterados: {diffusion['mean_bits_changed']:.2f} / {diffusion['total_bits']}")
        print(f"✓ Porcentagem: {diffusion['percentage']:.2f}% (ideal: ~50%)")
        
        # 4. Teste de Confusão
        print("\n[4/5] Executando teste de confusão...")
        confusion = runner.test_confusion(seed_size, num_tests=100)
        all_results['confusion'][f'seed_{seed_size}'] = confusion
        print(f"✓ Bits alterados: {confusion['mean_bits_changed']:.2f} / {confusion['total_bits']}")
        print(f"✓ Porcentagem: {confusion['percentage']:.2f}% (target: >40%)")
        
        print(f"\n✓ Testes concluídos para seed_size = {seed_size}")
    
    # 5. Teste de Chaves Equivalentes (executar uma vez)
    print(f"\n{'='*60}")
    print("Executando teste de chaves equivalentes...")
    print(f"{'='*60}")
    key_equiv = runner.test_key_equivalence(seed_size=32, num_samples=10000)
    all_results['key_equivalence'] = key_equiv
    print(f"✓ Amostras testadas: {key_equiv['samples_tested']}")
    print(f"✓ Pares equivalentes: {key_equiv['equivalent_pairs']}")
    print(f"✓ Taxa de colisão: {key_equiv['collision_rate']:.4f}%")
    
    # Salvar resultados em JSON
    print(f"\n{'='*60}")
    print("Salvando resultados...")
    print(f"{'='*60}")
    
    try:
        with open('results.json', 'w', encoding='utf-8') as f:
            json.dump(all_results, indent=2, fp=f)
        print("✓ Arquivo results.json criado com sucesso")
    except Exception as e:
        print(f"✗ Erro ao salvar results.json: {e}")
    
    # Gerar relatório em texto
    try:
        report_text = generate_text_report(all_results)
        with open('results.txt', 'w', encoding='utf-8') as f:
            f.write(report_text)
        print("✓ Arquivo results.txt criado com sucesso")
    except Exception as e:
        print(f"✗ Erro ao salvar results.txt: {e}")
    
    print(f"\n{'='*60}")
    print("EXECUÇÃO CONCLUÍDA COM SUCESSO!")
    print(f"{'='*60}")
    print("\nArquivos gerados:")
    print("  - results.json (dados estruturados)")
    print("  - results.txt (relatório detalhado)")


def generate_text_report(results: Dict) -> str:
    """
    Gera relatório detalhado em formato texto.
    
    Args:
        results: Dicionário com todos os resultados dos testes
        
    Returns:
        String com relatório formatado
    """
    report = []
    
    # Cabeçalho
    report.append("=" * 80)
    report.append("RELATÓRIO DE TESTES - ESQUEMA CRIPTOGRÁFICO SIMPLIFICADO")
    report.append("=" * 80)
    report.append("")
    report.append("Trabalho de Auditoria e Segurança da Informação")
    report.append(f"Data de execução: {results['metadata']['timestamp']}")
    report.append(f"Python version: {results['metadata']['python_version']}")
    report.append("")
    
    # Descrição do Trabalho
    report.append("=" * 80)
    report.append("1. DESCRIÇÃO DO TRABALHO")
    report.append("=" * 80)
    report.append("")
    report.append("Este trabalho implementa um esquema criptográfico simplificado com três funções:")
    report.append("")
    report.append("• GEN(seed): Gera chave binária de tamanho 4 * len(seed) usando expansão SHA-256")
    report.append("• ENC(K, M): Criptografa mensagem M usando chave K com múltiplas camadas")
    report.append("• DEC(K, C): Descriptografa cifra C usando chave K (operação reversa)")
    report.append("")
    report.append("Características da implementação:")
    report.append("- Geração de chave determinística baseada em SHA-256")
    report.append("- Criptografia com 4 rodadas de transformação")
    report.append("- Camadas de substituição (S-Box) e permutação (P-Box)")
    report.append("- Operações XOR com subchaves derivadas")
    report.append("")
    
    # Resultados de Correção
    report.append("=" * 80)
    report.append("2. TESTE DE CORREÇÃO")
    report.append("=" * 80)
    report.append("")
    report.append("Objetivo: Verificar que DEC(K, ENC(K, M)) = M para todos os casos")
    report.append("Iterações: 1000 testes por tamanho de seed")
    report.append("")
    report.append(f"{'Seed Size':<15} {'Testes Passados':<20} {'Taxa de Sucesso':<20}")
    report.append("-" * 55)
    
    for seed_key in sorted(results['correctness'].keys()):
        seed_size = seed_key.split('_')[1]
        c = results['correctness'][seed_key]
        report.append(f"{seed_size + ' bits':<15} {c['tests_passed']:<20} {c['success_rate']:.2f}%")
    
    report.append("")
    
    # Resultados de Desempenho
    report.append("=" * 80)
    report.append("3. TESTE DE DESEMPENHO")
    report.append("=" * 80)
    report.append("")
    report.append("Objetivo: Medir tempo de execução das funções")
    report.append("Iterações: 1000 medições por função")
    report.append("Unidade: milissegundos (ms)")
    report.append("")
    report.append(f"{'Seed':<10} {'GEN (ms)':<15} {'ENC (ms)':<15} {'DEC (ms)':<15} {'Total (ms)':<15}")
    report.append("-" * 70)
    
    for seed_key in sorted(results['performance'].keys()):
        seed_size = seed_key.split('_')[1]
        p = results['performance'][seed_key]
        report.append(
            f"{seed_size + ' bits':<10} "
            f"{p['gen_time_ms']:>6.4f} ±{p['gen_std']:>5.4f}  "
            f"{p['enc_time_ms']:>6.4f} ±{p['enc_std']:>5.4f}  "
            f"{p['dec_time_ms']:>6.4f} ±{p['dec_std']:>5.4f}  "
            f"{p['total_time_ms']:>6.4f}"
        )
    
    report.append("")
    
    # Resultados de Difusão
    report.append("=" * 80)
    report.append("4. TESTE DE DIFUSÃO (Efeito Avalanche)")
    report.append("=" * 80)
    report.append("")
    report.append("Objetivo: Avaliar propagação de mudanças (1 bit em M altera ~50% de C)")
    report.append("Método: Inverter cada bit de M e medir bits alterados em C")
    report.append("Iterações: 100 mensagens aleatórias por tamanho")
    report.append("")
    report.append(f"{'Seed':<10} {'Bits Alterados':<20} {'Porcentagem':<15} {'Avaliação':<15}")
    report.append("-" * 60)
    
    for seed_key in sorted(results['diffusion'].keys()):
        seed_size = seed_key.split('_')[1]
        d = results['diffusion'][seed_key]
        percentage = d['percentage']
        
        # Avaliar qualidade
        if 45 <= percentage <= 55:
            evaluation = "Excelente ✓"
        elif 40 <= percentage <= 60:
            evaluation = "Bom"
        else:
            evaluation = "Melhorar"
        
        report.append(
            f"{seed_size + ' bits':<10} "
            f"{d['mean_bits_changed']:.2f} / {d['total_bits']:<8} "
            f"{percentage:>6.2f}%{'':>7} "
            f"{evaluation}"
        )
    
    report.append("")
    
    # Resultados de Confusão
    report.append("=" * 80)
    report.append("5. TESTE DE CONFUSÃO")
    report.append("=" * 80)
    report.append("")
    report.append("Objetivo: Avaliar impacto de mudança na seed (1 bit na seed altera >40% de C)")
    report.append("Método: Inverter cada bit da seed e medir bits alterados em C")
    report.append("Iterações: 100 seeds aleatórias por tamanho")
    report.append("")
    report.append(f"{'Seed':<10} {'Bits Alterados':<20} {'Porcentagem':<15} {'Avaliação':<15}")
    report.append("-" * 60)
    
    for seed_key in sorted(results['confusion'].keys()):
        seed_size = seed_key.split('_')[1]
        c = results['confusion'][seed_key]
        percentage = c['percentage']
        
        # Avaliar qualidade
        if percentage >= 50:
            evaluation = "Excelente ✓"
        elif percentage >= 40:
            evaluation = "Bom"
        else:
            evaluation = "Melhorar"
        
        report.append(
            f"{seed_size + ' bits':<10} "
            f"{c['mean_bits_changed']:.2f} / {c['total_bits']:<8} "
            f"{percentage:>6.2f}%{'':>7} "
            f"{evaluation}"
        )
    
    report.append("")
    
    # Resultados de Chaves Equivalentes
    report.append("=" * 80)
    report.append("6. TESTE DE CHAVES EQUIVALENTES")
    report.append("=" * 80)
    report.append("")
    report.append("Objetivo: Detectar colisões (K1 ≠ K2 mas ENC(K1, M) = ENC(K2, M))")
    report.append(f"Seeds geradas: {results['key_equivalence']['total_seeds_generated']}")
    report.append(f"Amostras testadas: {results['key_equivalence']['samples_tested']}")
    report.append("")
    report.append(f"Pares equivalentes encontrados: {results['key_equivalence']['equivalent_pairs']}")
    report.append(f"Taxa de colisão: {results['key_equivalence']['collision_rate']:.4f}%")
    report.append("")
    
    if results['key_equivalence']['equivalent_pairs'] == 0:
        report.append("✓ EXCELENTE: Nenhuma colisão detectada!")
    else:
        report.append("⚠ ATENÇÃO: Colisões detectadas. Considerar melhorias no algoritmo.")
    
    report.append("")
    
    # Análise e Conclusões
    report.append("=" * 80)
    report.append("7. ANÁLISE E CONCLUSÕES")
    report.append("=" * 80)
    report.append("")
    
    # Análise de correção
    all_correct = all(
        results['correctness'][k]['success_rate'] == 100.0 
        for k in results['correctness']
    )
    
    if all_correct:
        report.append("✓ CORREÇÃO: Implementação 100% correta em todos os testes")
    else:
        report.append("✗ CORREÇÃO: Erros detectados - revisar implementação")
    
    report.append("")
    
    # Análise de difusão
    avg_diffusion = sum(
        results['diffusion'][k]['percentage'] 
        for k in results['diffusion']
    ) / len(results['diffusion'])
    
    report.append(f"✓ DIFUSÃO: Média de {avg_diffusion:.2f}% de bits alterados")
    if 45 <= avg_diffusion <= 55:
        report.append("  → Excelente propriedade de difusão (próximo ao ideal de 50%)")
    elif 40 <= avg_diffusion <= 60:
        report.append("  → Boa propriedade de difusão")
    else:
        report.append("  → Difusão pode ser melhorada")
    
    report.append("")
    
    # Análise de confusão
    avg_confusion = sum(
        results['confusion'][k]['percentage'] 
        for k in results['confusion']
    ) / len(results['confusion'])
    
    report.append(f"✓ CONFUSÃO: Média de {avg_confusion:.2f}% de bits alterados")
    if avg_confusion >= 50:
        report.append("  → Excelente propriedade de confusão")
    elif avg_confusion >= 40:
        report.append("  → Boa propriedade de confusão")
    else:
        report.append("  → Confusão pode ser melhorada")
    
    report.append("")
    
    # Análise de desempenho
    perf_32 = results['performance'].get('seed_32', {})
    if perf_32:
        report.append("✓ DESEMPENHO (seed=32 bits):")
        report.append(f"  → GEN: {perf_32['gen_time_ms']:.4f} ms")
        report.append(f"  → ENC: {perf_32['enc_time_ms']:.4f} ms")
        report.append(f"  → DEC: {perf_32['dec_time_ms']:.4f} ms")
        report.append(f"  → Total: {perf_32['total_time_ms']:.4f} ms")
    
    report.append("")
    
    # Conclusão final
    report.append("-" * 80)
    report.append("CONCLUSÃO FINAL:")
    report.append("")
    report.append("Este trabalho implementou com sucesso um esquema criptográfico simplificado")
    report.append("que demonstra os conceitos fundamentais de criptografia simétrica:")
    report.append("")
    report.append("• Geração determinística de chaves")
    report.append("• Propriedades de difusão e confusão")
    report.append("• Operações reversíveis de criptografia/descriptografia")
    report.append("")
    report.append("A implementação atende aos requisitos do trabalho e demonstra")
    report.append("boas propriedades criptográficas para fins educacionais.")
    report.append("")
    report.append("=" * 80)
    
    return '\n'.join(report)


if __name__ == '__main__':
    main()
