# Esquema Criptográfico Simplificado

## 📋 Descrição

Este projeto implementa um esquema criptográfico educacional em Python 3.10 com três funções principais: geração de chave (GEN), criptografia (ENC) e descriptografia (DEC). Desenvolvido como trabalho acadêmico para a disciplina de Auditoria e Segurança da Informação.

**⚠️ AVISO IMPORTANTE**: Este é um esquema educacional. **NÃO use em produção**. Não passou por análise criptográfica formal.

## 🎯 Objetivo

Demonstrar conceitos fundamentais de criptografia simétrica:
- Geração determinística de chaves
- Propriedades de difusão e confusão
- Operações reversíveis de criptografia/descriptografia
- Testes de qualidade criptográfica

## 🏗️ Estrutura do Projeto

```
asi/
├── .loop/
│   └── specs/
│       └── crypto-scheme/          # Especificações detalhadas
│           ├── 001-crypto-scheme-bus-spec.md
│           ├── 002-crypto-scheme-tech-spec.md
│           ├── 003-crypto-scheme-plan.md
│           ├── 004-crypto-scheme-tasks-list.md
│           └── 005-crypto-scheme-test-plan.md
├── crypto_scheme.py                # Módulo principal (GEN, ENC, DEC)
├── tests.py                        # Suite de testes
├── main.py                         # Script de execução
├── slides_generator.py             # Gerador de apresentação
├── requirements.txt                # Dependências
├── results.json                    # Resultados estruturados (gerado)
├── results.txt                     # Relatório detalhado (gerado)
├── slides_content.md              # Conteúdo dos slides (gerado)
└── README.md                       # Este arquivo
```

## 🚀 Instalação

### Requisitos

- Python 3.10 ou superior
- pip (gerenciador de pacotes Python)

### Passos

1. Clone ou baixe este repositório

2. Navegue até o diretório do projeto:
```bash
cd asi
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

## 💻 Uso

### Executar Todos os Testes

Para executar a suite completa de testes e gerar relatórios:

```bash
python main.py
```

Este comando irá:
- Testar correção (DEC(K, ENC(K, M)) = M)
- Medir desempenho (tempos de execução)
- Avaliar difusão (efeito avalanche)
- Avaliar confusão (impacto de mudança na seed)
- Detectar chaves equivalentes
- Gerar `results.json` e `results.txt`

### Gerar Slides

Após executar os testes, gere o conteúdo para apresentação:

```bash
python slides_generator.py
```

Isso criará o arquivo `slides_content.md` com 4 slides em formato Markdown.

### Uso das Funções

```python
from crypto_scheme import CryptoScheme

# Inicializar
crypto = CryptoScheme()

# Gerar chave a partir de seed
seed = [1, 0, 1, 1, 0, 1, 0, 1]  # 8 bits
key = crypto.GEN(seed)            # 32 bits (4 × seed)

# Criptografar mensagem
message = [1, 0] * 16             # 32 bits
cipher = crypto.ENC(key, message)

# Descriptografar
decrypted = crypto.DEC(key, cipher)

# Verificar correção
assert message == decrypted
```

## 🔬 Funções Implementadas

### GEN(seed)

Gera chave binária determinística a partir de uma seed.

- **Entrada**: Lista de bits (0 ou 1)
- **Saída**: Chave com tamanho 4 × len(seed)
- **Método**: Expansão usando SHA-256 com contador
- **Propriedade**: Mesma seed sempre gera mesma chave

### ENC(K, M)

Criptografa mensagem usando chave.

- **Entrada**: Chave K e mensagem M (mesmo tamanho)
- **Saída**: Cifra C (mesmo tamanho)
- **Camadas** (4 rodadas):
  1. XOR com subchave derivada
  2. S-Box (substituição não-linear)
  3. P-Box (permutação determinística)

### DEC(K, C)

Descriptografa cifra usando chave.

- **Entrada**: Chave K e cifra C (mesmo tamanho)
- **Saída**: Mensagem original M
- **Método**: Aplicação reversa das transformações de ENC

## 📊 Testes Implementados

### 1. Teste de Correção
Verifica que DEC(K, ENC(K, M)) = M para 1000 casos aleatórios.

### 2. Teste de Desempenho
Mede tempo de execução de GEN, ENC e DEC para diferentes tamanhos de seed (8, 16, 32, 64, 128 bits).

### 3. Teste de Difusão
Avalia o efeito avalanche: mudança de 1 bit na mensagem deve alterar aproximadamente 50% dos bits da cifra.

### 4. Teste de Confusão
Avalia impacto de mudança na seed: mudança de 1 bit na seed deve alterar significativamente a cifra (>40%).

### 5. Teste de Chaves Equivalentes
Detecta colisões: verifica se existem K1 ≠ K2 que produzem a mesma cifra para uma mensagem fixa.

## 📈 Resultados Esperados

### Desempenho (seed=32 bits)
- GEN: < 0.1 ms
- ENC: < 1.0 ms
- DEC: < 1.0 ms

### Qualidade
- Correção: 100%
- Difusão: ~50% (ideal)
- Confusão: >25%
- Colisões: 0

## 📄 Arquivos de Saída

### results.json
Dados estruturados em formato JSON com todas as métricas dos testes.

### results.txt
Relatório detalhado em texto legível com:
- Descrição do trabalho
- Resultados de todos os testes
- Análises e conclusões

### slides_content.md
Conteúdo para apresentação (4 slides) em formato Markdown:
1. Título e Introdução
2. Implementação (GEN, ENC, DEC)
3. Resultados dos Testes
4. Conclusões

## 🔧 Tecnologias Utilizadas

- **Python 3.10**: Linguagem de programação
- **hashlib**: Funções hash (SHA-256)
- **typing**: Type hints para clareza
- **json**: Serialização de resultados

## 📚 Conceitos Criptográficos

### Difusão
Mudanças em texto plano devem se espalhar pela cifra. Implementado através de:
- Múltiplas rodadas de transformação
- P-Box (permutação de bits)

### Confusão
Relação complexa entre chave e cifra. Implementado através de:
- S-Box (substituição não-linear)
- Derivação de subchaves com SHA-256

### Reversibilidade
Todas as operações são invertíveis:
- XOR é auto-inverso
- S-Box tem S-Box inversa
- P-Box tem P-Box inversa

## ⚠️ Limitações

- **Não é criptografia de nível profissional**
- **Não foi submetido a análise criptográfica formal**
- **Propósito exclusivamente educacional**
- S-Box e P-Box não foram otimizadas para máxima segurança
- Sem proteção contra ataques de canal lateral
- Sem autenticação de mensagem

## 📝 Licença

Este projeto foi desenvolvido para fins acadêmicos.

## 👨‍💻 Desenvolvimento

Para contribuir ou modificar:

1. Leia as especificações em `.loop/specs/crypto-scheme/`
2. Modifique os arquivos necessários
3. Execute os testes: `python main.py`
4. Verifique as métricas de qualidade

## 📞 Suporte

Para dúvidas sobre o projeto, consulte:
- Especificações técnicas: `002-crypto-scheme-tech-spec.md`
- Plano de implementação: `003-crypto-scheme-plan.md`
- Lista de tarefas: `004-crypto-scheme-tasks-list.md`

---

**Data de Criação**: Janeiro 2026  
**Versão**: 1.0.0
