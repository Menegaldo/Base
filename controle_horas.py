import os
import sys
import json
import base64
import getpass
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

# ====== Dependência ======
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Instale a dependência: pip install cryptography")
    sys.exit(1)

# ====== Config ======
ARQUIVO_LOG = "registro.txt"        # armazenado CIFRADO (ou migrado na 1ª execução)
ARQUIVO_TEMP = ".atividade_em_andamento"
ARQUIVO_METAS = "metas.json.enc"    # metas semanais cifradas
META_SEMANAL = timedelta(hours=40)
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

_PASS = None  # senha no runtime

# =================== CRIPTO ===================

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def cifrar(plaintext: bytes, passphrase: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aes.encrypt(nonce, plaintext, None)
    return "|".join(["v1", _b64e(salt), _b64e(nonce), _b64e(ct)]).encode("utf-8")

def decifrar(blob: bytes, passphrase: str) -> bytes:
    parts = blob.decode("utf-8", errors="strict").split("|")
    if len(parts) != 4 or parts[0] != "v1":
        raise ValueError("Formato inválido")
    salt = _b64d(parts[1]); nonce = _b64d(parts[2]); ct = _b64d(parts[3])
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)

def _arquivo_cifrado() -> bool:
    if not os.path.exists(ARQUIVO_LOG):
        return False
    try:
        with open(ARQUIVO_LOG, "rb") as f:
            head = f.read(3)
        return head == b"v1|"
    except:
        return False

def _carregar_texto(passphrase: str) -> str:
    if not os.path.exists(ARQUIVO_LOG):
        return ""
    with open(ARQUIVO_LOG, "rb") as f:
        blob = f.read()
    pt = decifrar(blob, passphrase)
    return pt.decode("utf-8", errors="replace")

def _salvar_texto(passphrase: str, texto: str) -> None:
    blob = cifrar(texto.encode("utf-8"), passphrase)
    with open(ARQUIVO_LOG, "wb") as f:
        f.write(blob)

def _migrar_plaintext_para_cifrado(nova_senha: str):
    with open(ARQUIVO_LOG, "r", encoding="utf-8", errors="replace") as f:
        texto = f.read()
    texto = ordenar_e_formatar_texto(texto)
    _salvar_texto(nova_senha, texto)
    print("✔️  Arquivo existente migrado para formato cifrado.")

def _requisitar_senha_inicial() -> str:
    # Não existe -> criar com nova senha
    if not os.path.exists(ARQUIVO_LOG):
        while True:
            pwd = getpass.getpass("Defina a senha do registro: ")
            conf = getpass.getpass("Confirmar senha: ")
            if pwd and pwd == conf:
                print("✔️  Senha definida.")
                return pwd
            print("❌ Senhas não conferem.")
    # Já cifrado -> validar
    if _arquivo_cifrado():
        while True:
            pwd = getpass.getpass("Senha do registro: ")
            try:
                _ = _carregar_texto(pwd)
                print("✔️  Senha OK.")
                return pwd
            except Exception:
                print("❌ Senha incorreta.")
    # Texto puro -> migrar
    print("⚠️ Arquivo existente está em texto puro. Vamos cifrar agora.")
    while True:
        pwd = getpass.getpass("Defina a senha do registro: ")
        conf = getpass.getpass("Confirmar senha: ")
        if pwd and pwd == conf:
            _migrar_plaintext_para_cifrado(pwd)
            return pwd
        print("❌ Senhas não conferem.")

# =================== METAS SEMANAIS (CIFRADAS) ===================

def _week_key_tuple_to_label(sem_key):
    return f"{sem_key[0]}-S{sem_key[1]:02d}"

def _week_label_to_tuple(lbl):
    try:
        ano, ssem = lbl.split("-S")
        return (int(ano), int(ssem))
    except:
        return None

def _carregar_metas(passphrase: str) -> dict:
    if not os.path.exists(ARQUIVO_METAS):
        return {}
    with open(ARQUIVO_METAS, "rb") as f:
        blob = f.read()
    try:
        pt = decifrar(blob, passphrase).decode("utf-8", errors="replace")
        data = json.loads(pt)
        if isinstance(data, dict):
            return {k: int(v) for k, v in data.items()}
        return {}
    except Exception:
        return {}

def _salvar_metas(passphrase: str, metas: dict) -> None:
    try:
        pt = json.dumps(metas, ensure_ascii=False).encode("utf-8")
        blob = cifrar(pt, passphrase)
        with open(ARQUIVO_METAS, "wb") as f:
            f.write(blob)
    except Exception as e:
        print(f"❌ Falha ao salvar metas: {e}")

# =================== NORMALIZAÇÃO ===================

def normalizar_data(data_input):
    entrada = data_input.strip().lower().replace('.', '/')
    if entrada == "hoje":
        return datetime.now().strftime("%Y-%m-%d")
    formatos = ("%d/%m/%Y", "%Y-%m-%d", "%d/%m/%y")
    for fmt in formatos:
        try:
            dt = datetime.strptime(entrada, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    print("❌ Data inválida. Use 'hoje', 'dd/mm/aaaa', 'dd.mm.aa' ou 'aaaa-mm-dd'")
    return None

def normalizar_hora(h):
    s = h.strip().lower().replace(" ", "").replace(".", ":")
    if not s:
        print("❌ Hora vazia."); return None
    if ":" in s:
        hh, mm = s.split(":", 1)
        if hh == "": print("❌ Hora inválida."); return None
        if mm == "": mm = "0"
    else:
        if not s.isdigit(): print("❌ Hora inválida."); return None
        if len(s) <= 2: hh, mm = s, "0"
        elif len(s) in (3, 4): hh, mm = s[:-2], s[-2:]
        else: print("❌ Hora inválida."); return None
    try:
        h_int = int(hh); m_int = int(mm)
        if not (0 <= h_int <= 23 and 0 <= m_int <= 59): raise ValueError
        return f"{h_int:02d}:{m_int:02d}"
    except ValueError:
        print("❌ Hora fora do intervalo (00:00–23:59)."); return None

# =================== PARSE / TOTAIS ===================

def parse_linha_log(linha):
    try:
        s = linha.strip()
        if not s or s == "----x----":
            return None, None, timedelta(0)
        parte1, _ = s.split("|", 1)
        data_str, horario = parte1.strip().split("]", 1)
        data = data_str.strip("[")
        inicio, fim = [x.strip() for x in horario.strip().split(" - ")]
        dt_inicio = datetime.strptime(f"{data} {inicio}", "%Y-%m-%d %H:%M")
        dt_fim = datetime.strptime(f"{data} {fim}", "%Y-%m-%d %H:%M")
        if dt_fim < dt_inicio:
            dt_fim += timedelta(days=1)
        duracao = dt_fim - dt_inicio
        semana = dt_inicio.isocalendar()[:2]  # (ano_iso, semana_iso)
        mes = dt_inicio.strftime("%Y-%m")
        return semana, mes, duracao
    except:
        return None, None, timedelta(0)

def calcular_totais(texto_plain: str):
    semanais = defaultdict(timedelta)
    mensais = defaultdict(timedelta)
    if not texto_plain:
        return semanais, mensais
    for linha in texto_plain.splitlines():
        semana, mes, dur = parse_linha_log(linha)
        if semana and mes:
            semanais[semana] += dur
            mensais[mes] += dur
    return semanais, mensais

# =================== BANCO / META ===================

def _fmt_hhmm(td: timedelta) -> str:
    s = int(td.total_seconds()); s = max(s, 0)
    h = s // 3600; m = (s % 3600) // 60
    return f"{h}h{m:02d}m"

def _fmt_hhmm_signed(td: timedelta, show_plus: bool = False) -> str:
    s = int(td.total_seconds())
    sign = ""
    if s < 0:
        sign = "-"
        s = -s
    elif show_plus:
        sign = "+"
    h = s // 3600; m = (s % 3600) // 60
    return f"{sign}{h}h{m:02d}m"

def _calc_banco_e_meta(semanais: dict, metas: dict):
    ano_atual, sem_atual, _ = datetime.now().isocalendar()
    chave_atual = (ano_atual, sem_atual)

    def _meta_para(sem_key):
        lbl = _week_key_tuple_to_label(sem_key)
        h = metas.get(lbl, int(META_SEMANAL.total_seconds() // 3600))
        return timedelta(hours=h)

    banco_antes = timedelta(0)
    for (ano, sem), t in sorted(semanais.items()):
        if (ano, sem) < chave_atual:
            banco_antes += (t - _meta_para((ano, sem)))

    trab_atual = semanais.get(chave_atual, timedelta(0))
    meta_sem_atual = _meta_para(chave_atual)
    delta_atual = trab_atual - meta_sem_atual
    banco_depois = banco_antes + delta_atual

    banco_usado = timedelta(0)
    if banco_antes > timedelta(0) and trab_atual < meta_sem_atual:
        banco_usado = min(banco_antes, meta_sem_atual - trab_atual)

    faltam = meta_sem_atual - trab_atual - banco_antes
    if faltam < timedelta(0):
        faltam = timedelta(0)

    return (f"{ano_atual}-S{sem_atual:02d}",
            trab_atual, faltam, banco_antes, banco_usado, banco_depois, delta_atual,
            int(meta_sem_atual.total_seconds() // 3600))

# =================== ORDENAR / FORMATAR ===================

def _extrair_campos(linha):
    linha = linha.strip()
    if not linha or linha == "----x----":
        return None
    try:
        parte1, atividade = linha.split("|", 1)
        data_str = parte1[parte1.find("[")+1:parte1.find("]")]
        horas = parte1[parte1.find("]")+1:].strip()
        inicio, fim = [x.strip() for x in horas.split(" - ")]
        return data_str.strip(), inicio, fim, atividade.strip()
    except:
        return None

def ordenar_e_formatar_texto(texto_plain: str) -> str:
    entradas = []
    for linha in texto_plain.splitlines():
        dados = _extrair_campos(linha)
        if not dados:
            continue
        data_str, ini, fim, atividade = dados
        ini_fmt = normalizar_hora(ini)
        fim_fmt = normalizar_hora(fim)
        if not ini_fmt or not fim_fmt:
            continue
        try:
            dt_inicio = datetime.strptime(f"{data_str} {ini_fmt}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        entradas.append((dt_inicio, data_str, ini_fmt, fim_fmt, atividade))

    entradas.sort(key=lambda x: (x[0], x[2]))

    linhas_out = []
    prev_week = None
    prev_date = None
    for dt_inicio, data_str, ini_fmt, fim_fmt, atividade in entradas:
        week = dt_inicio.isocalendar()[:2]
        if prev_week is not None and week != prev_week:
            linhas_out.append("----x----")
        elif prev_date is not None and data_str != prev_date:
            linhas_out.append("")
        linhas_out.append(f"[{data_str}] {ini_fmt} - {fim_fmt} | {atividade}")
        prev_week = week
        prev_date = data_str

    return "\n".join(linhas_out) + ("\n" if linhas_out else "")

# ===== Histórico sem descrição (NÃO USADO NO MENU NOVO) =====

def _historico_sem_descricao(texto_plain: str) -> str:
    out = []
    for linha in texto_plain.splitlines():
        s = linha.rstrip("\n")
        if not s or s == "----x----":
            out.append(s); continue
        if "|" in s:
            parte1, _ = s.split("|", 1)
            out.append(parte1.rstrip() + " | ")
        else:
            out.append(s)
    return "\n".join(out) + ("\n" if out else "")

# ===== Impressão alinhada =====

def _print_kv_block(pairs, title):
    pairs = [(k, v) for (k, v) in pairs if v is not None]
    w = max((len(k) for k, _ in pairs), default=0)
    linha = "-" * max(36, w + 12)
    print("\n" + linha)
    print(f"   {title}")
    print(linha)
    for k, v in pairs:
        print(f"{k.ljust(w)}  {v}")

# =================== EXIBIÇÃO ===================

def exibir_totais(texto_plain: str):
    semanais, _ = calcular_totais(texto_plain)
    metas = _carregar_metas(_PASS)

    print("\n=== Total por Semana ===")
    for (ano, semana), tempo in sorted(semanais.items()):
        lbl = f"{ano}-S{semana:02d}"
        horas = int(tempo.total_seconds() // 3600)
        minutos = int((tempo.total_seconds() % 3600) // 60)
        meta_h = metas.get(lbl, int(META_SEMANAL.total_seconds() // 3600))
        print(f"{lbl}  {horas:02d}h{minutos:02d}m ({meta_h}h)")

    sem_str, trab_atual, faltam, banco_antes, banco_usado, banco_depois, delta_atual, meta_atual = _calc_banco_e_meta(semanais, metas)

    pairs_banco = [
        ("Saldo até semana anterior:",     _fmt_hhmm_signed(banco_antes, show_plus=True)),
        ("Usado nesta semana:",            _fmt_hhmm(banco_usado) if banco_usado > timedelta(0) else None),
        (f"Delta da semana {sem_str}:",    _fmt_hhmm_signed(delta_atual, show_plus=True)),
        ("Saldo após esta semana:",        _fmt_hhmm_signed(banco_depois, show_plus=True)),
    ]
    _print_kv_block(pairs_banco, "BANCO DE HORAS")

    pairs_meta = [
        ("Trabalhado na semana:",           _fmt_hhmm(trab_atual)),
        ("Meta desta semana:",              f"{meta_atual}h00m"),
        ("Faltam p/ meta (com saldo):",     _fmt_hhmm(faltam)),
    ]
    _print_kv_block(pairs_meta, f"META SEMANAL [{sem_str}]")

# ===== Fechamento automático de semana =====

def _ultima_semana_no_texto(texto_plain: str):
    ultima = None
    for linha in texto_plain.splitlines():
        semana, _, _ = parse_linha_log(linha)
        if semana:
            if (ultima is None) or (semana > ultima):
                ultima = semana
    return ultima

def _imprimir_fechamento_semana(sem_key, texto_plain: str):
    semanais, _ = calcular_totais(texto_plain)
    metas = _carregar_metas(_PASS)

    def _meta_para(sk):
        lbl = _week_key_tuple_to_label(sk)
        h = metas.get(lbl, int(META_SEMANAL.total_seconds() // 3600))
        return timedelta(hours=h)

    banco_antes = timedelta(0)
    for (ano, sem), t in sorted(semanais.items()):
        if (ano, sem) < sem_key:
            banco_antes += (t - _meta_para((ano, sem)))

    trabalhado = semanais.get(sem_key, timedelta(0))
    meta_sem = _meta_para(sem_key)
    delta = trabalhado - meta_sem
    banco_depois = banco_antes + delta
    sem_str = f"{sem_key[0]}-S{sem_key[1]:02d}"

    pairs = [
        ("Trabalhado na semana:",  _fmt_hhmm(trabalhado)),
        ("Meta semanal:",          _fmt_hhmm(meta_sem)),
        ("Diferença (Δ):",         _fmt_hhmm_signed(delta, show_plus=True)),
        ("Saldo anterior:",        _fmt_hhmm_signed(banco_antes, show_plus=True)),
        ("Saldo após fechamento:", _fmt_hhmm_signed(banco_depois, show_plus=True)),
    ]
    _print_kv_block(pairs, f"FECHAMENTO DA SEMANA {sem_str}")

def _fechar_semana_passada_se_necessario(texto_plain: str, data_nova_iso: str):
    try:
        dt_nova = datetime.strptime(data_nova_iso, "%Y-%m-%d")
    except ValueError:
        return
    sem_nova = dt_nova.isocalendar()[:2]
    sem_ultima = _ultima_semana_no_texto(texto_plain)
    if sem_ultima and sem_ultima < sem_nova:
        _imprimir_fechamento_semana(sem_ultima, texto_plain)

# =================== OPERAÇÕES ===================

def exibir_logs_ordenados_e_salvar(texto: str) -> str:
    texto = ordenar_e_formatar_texto(texto)
    _salvar_texto(_PASS, texto)
    return texto

def registrar_entrada():
    global _PASS
    print("=== Registro de atividade (manual) ===")
    data_input = input("Data (ou 'hoje'): ")
    data_final = normalizar_data(data_input)
    if not data_final: return

    texto_atual = _carregar_texto(_PASS)
    _fechar_semana_passada_se_necessario(texto_atual, data_final)

    hora_inicio = normalizar_hora(input("Hora de início (ex: 8.00 ou 08:30): "))
    if not hora_inicio: return
    hora_fim = normalizar_hora(input("Hora de término (ex: 12.00 ou 12:00): "))
    if not hora_fim: return
    atividade = input("Descreva a atividade realizada: ").strip()

    texto = texto_atual + f"[{data_final}] {hora_inicio} - {hora_fim} | {atividade}\n"
    texto = exibir_logs_ordenados_e_salvar(texto)

    print("✅ Atividade registrada.")
    exibir_totais(texto)

def mostrar_logs():
    global _PASS
    if not os.path.exists(ARQUIVO_LOG):
        print("❌ Nenhum registro encontrado.")
        exibir_totais("")
        return
    texto = _carregar_texto(_PASS)
    texto = exibir_logs_ordenados_e_salvar(texto)
    print("\n=== Histórico de Atividades ===")
    print(texto, end="")
    exibir_totais(texto)

# --- NOVA OPÇÃO 5: mostrar apenas os totais ---
def mostrar_apenas_totais():
    global _PASS
    texto = _carregar_texto(_PASS) if os.path.exists(ARQUIVO_LOG) else ""
    if texto:
        texto = exibir_logs_ordenados_e_salvar(texto)
    exibir_totais(texto)

# --- NOVA OPÇÃO 6: "Lançado no Kace" -> marcar 'x' até data ---
def lancado_no_kace():
    """
    Marca com ' x' todas as entradas até a data informada (inclusive).
    Serve de indicador de que já foram lançadas no Kace.
    """
    global _PASS
    if not os.path.exists(ARQUIVO_LOG):
        print("❌ Nenhum registro encontrado."); return

    texto = _carregar_texto(_PASS)

    data_input = input("Marcar 'x' até a data (ou 'hoje'): ").strip()
    data_final = normalizar_data(data_input)
    if not data_final:
        return
    try:
        dt_lim = datetime.strptime(data_final, "%Y-%m-%d")
    except ValueError:
        print("❌ Data inválida."); return

    novas_linhas = []
    marcados = 0

    for l in texto.splitlines():
        s = l.strip()
        if not s or s == "----x----":
            novas_linhas.append(l)
            continue
        dados = _extrair_campos(l)
        if not dados:
            novas_linhas.append(l)
            continue

        data_str, ini, fim, atividade = dados
        try:
            dt = datetime.strptime(data_str, "%Y-%m-%d")
        except:
            novas_linhas.append(l)
            continue

        if dt <= dt_lim:
            if not atividade.endswith(" x"):
                atividade = (atividade + " x").rstrip()
                marcados += 1
            ini_fmt = normalizar_hora(ini) or ini
            fim_fmt = normalizar_hora(fim) or fim
            novas_linhas.append(f"[{data_str}] {ini_fmt} - {fim_fmt} | {atividade}")
        else:
            novas_linhas.append(l)

    texto_novo = "\n".join(novas_linhas) + ("\n" if novas_linhas else "")
    texto_novo = ordenar_e_formatar_texto(texto_novo)
    _salvar_texto(_PASS, texto_novo)
    print(f"✔️ Marcados com 'x': {marcados}")

def definir_meta_semanal():
    """
    Define/atualiza a meta de horas para UMA semana ISO específica.
    Ex.: Ano=2025, Semana=35, Meta=25 (horas)
    """
    global _PASS
    try:
        ano = int(input("Ano ISO (YYYY): ").strip())
        sem = int(input("Semana ISO (1-53): ").strip())
        if not (1 <= sem <= 53):
            print("❌ Semana inválida."); return
        meta_horas = int(input("Meta em horas (ex: 40 ou 25): ").strip())
        if meta_horas <= 0 or meta_horas > 168:
            print("❌ Meta fora do intervalo plausível."); return
    except ValueError:
        print("❌ Entradas inválidas."); return

    lbl = f"{ano}-S{sem:02d}"
    metas = _carregar_metas(_PASS)
    metas[lbl] = meta_horas
    _salvar_metas(_PASS, metas)
    print(f"✔️ Meta da semana {lbl} definida para {meta_horas}h.")

# =================== SENHA ===================

def alterar_senha():
    global _PASS
    print("=== Alterar senha ===")
    atual = getpass.getpass("Senha atual: ")
    if atual != _PASS:
        print("❌ Senha atual incorreta.")
        return
    novo = getpass.getpass("Nova senha: ")
    conf = getpass.getpass("Confirmar nova senha: ")
    if not novo or novo != conf:
        print("❌ Nova senha e confirmação não conferem.")
        return
    try:
        texto = _carregar_texto(_PASS)
        metas = _carregar_metas(_PASS)
    except Exception:
        print("❌ Falha ao ler com a senha atual.")
        return
    _salvar_texto(novo, texto)
    _salvar_metas(novo, metas)
    _PASS = novo
    print("✔️  Senha alterada e arquivos re-cifrados.")

# =================== MENU ===================

def menu():
    while True:
        print("\nEscolha uma opção:")
        print("1. Iniciar atividade agora")
        print("2. Finalizar atividade em andamento")
        print("3. Registrar atividade manualmente")
        print("4. Ver histórico e totais")
        print("5. Mostrar apenas totais")  # alterado
        print("6. Lançado no Kace (marcar 'x' até data)")  # alterado
        print("7. Alterar senha (re-cifrar arquivo)")
        print("8. Remover entrada por número")
        print("9. Definir meta semanal por semana (ISO)")
        print("0. Sair")
        opcao = input("Opção: ").strip()
        if opcao == "1":
            iniciar_atividade()
        elif opcao == "2":
            finalizar_atividade()
        elif opcao == "3":
            registrar_entrada()
        elif opcao == "4":
            mostrar_logs()
        elif opcao == "5":
            mostrar_apenas_totais()
        elif opcao == "6":
            lancado_no_kace()
        elif opcao == "7":
            alterar_senha()
        elif opcao == "8":
            remover_entrada_por_indice()
        elif opcao == "9":
            definir_meta_semanal()
        elif opcao == "0":
            print("Saindo..."); break
        else:
            print("❌ Opção inválida. Tente novamente.")

# ===== Atividade em andamento =====

def _ler_atividade_temp():
    if not os.path.exists(ARQUIVO_TEMP): return None
    with open(ARQUIVO_TEMP, "r") as f:
        conteudo = f.read().strip()
    try:
        data, hora_inicio, atividade = conteudo.split("|", 2)
        return data, hora_inicio, atividade
    except ValueError:
        return None

def iniciar_atividade():
    existente = _ler_atividade_temp()
    if existente:
        print("⚠️ Já existe atividade em andamento.")
        if input("Sobrescrever? (digite 'sim' para confirmar): ").strip().lower() != "sim":
            print("❌ Cancelado."); return
    atividade = input("Atividade: ").strip()
    data = datetime.now().strftime("%Y-%m-%d")
    hora_inicio = datetime.now().strftime("%H:%M")
    with open(ARQUIVO_TEMP, "w") as f:
        f.write(f"{data}|{hora_inicio}|{atividade}")
    print(f"▶️ Iniciada: [{data}] {hora_inicio} | {atividade}")

def finalizar_atividade():
    global _PASS
    info = _ler_atividade_temp()
    if not info:
        print("❌ Nenhuma atividade em andamento."); return
    data, hora_inicio, atividade = info

    texto_atual = _carregar_texto(_PASS)
    _fechar_semana_passada_se_necessario(texto_atual, data)

    fim_input = input("Hora de término (ex: 12.00 ou 12:00) [agora]: ").strip().lower()
    if fim_input in ("", "agora"):
        hora_fim = datetime.now().strftime("%H:%M")
    else:
        hora_fim = normalizar_hora(fim_input)
        if not hora_fim: return
    hora_inicio = normalizar_hora(hora_inicio) or hora_inicio
    texto = texto_atual + f"[{data}] {hora_inicio} - {hora_fim} | {atividade}\n"
    texto = exibir_logs_ordenados_e_salvar(texto)
    os.remove(ARQUIVO_TEMP)
    print(f"⏹️ Finalizada e registrada: [{data}] {hora_inicio} - {hora_fim} | {atividade}")
    exibir_totais(texto)

# ===== Main =====

if __name__ == "__main__":
    _PASS = _requisitar_senha_inicial()
    if not os.path.exists(ARQUIVO_LOG):
        _salvar_texto(_PASS, "")
    menu()
