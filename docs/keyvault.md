# Azure Key Vault — Quick Start

Elimine credenciais em texto plano usando o Azure Key Vault como fonte das credenciais do Service Principal.

> Guia completo de autenticação: [authentication.md](authentication.md)

---

## Pré-requisitos

- Key Vault criado no Azure
- Role **Key Vault Secrets User** atribuída ao seu usuário ou SP no vault
- `pip install fabricgov[keyvault]`

---

## 1. Criar os secrets no vault

```bash
az keyvault secret set --vault-name MEU-VAULT --name fabricgov-tenant-id     --value "<tenant-id>"
az keyvault secret set --vault-name MEU-VAULT --name fabricgov-client-id     --value "<client-id>"
az keyvault secret set --vault-name MEU-VAULT --name fabricgov-client-secret --value "<client-secret>"
```

Os nomes `fabricgov-*` são o padrão da ferramenta. Você pode usar qualquer nome — veja a seção [Nomes personalizados](#nomes-personalizados).

---

## 2. Autenticar no fabricgov

```bash
fabricgov auth keyvault --vault-url https://MEU-VAULT.vault.azure.net/
```

O fabricgov vai:
1. Conectar ao vault via `DefaultAzureCredential` (usa `az login` localmente)
2. Buscar os 3 secrets
3. Validar o token no Microsoft Fabric
4. Salvar apenas a URL e os nomes dos secrets em `output/.auth_config.json`

---

## 3. Coletar normalmente

```bash
fabricgov collect all
```

A cada execução, o fabricgov busca as credenciais diretamente do vault — sem nenhum secret em disco.

---

## Nomes personalizados

Se o seu vault já tem secrets com outros nomes:

```bash
fabricgov auth keyvault \
  --vault-url          https://MEU-VAULT.vault.azure.net/ \
  --tenant-id-secret   corp-fabric-tenant \
  --client-id-secret   corp-fabric-client \
  --client-secret-secret corp-fabric-secret
```

---

## Autenticação no vault por ambiente

| Ambiente | Como autenticar no vault |
|---|---|
| **Local** | `az login` antes de usar o fabricgov |
| **Azure VM / ACI** | Managed Identity (sem configuração extra) |
| **CI/CD** | Env vars `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` de um SP com acesso ao vault |

---

## Erros comuns

**`Dependências do Key Vault não encontradas`**
```bash
pip install fabricgov[keyvault]
```

**`CredentialUnavailableError` / sem acesso ao vault**
- Execute `az login` (desenvolvimento local)
- Ou verifique se a Managed Identity está habilitada na VM/container

**`ResourceNotFoundError: secret not found`**
- Confirme os nomes dos secrets no portal do vault
- Use `--tenant-id-secret`, `--client-id-secret`, `--client-secret-secret` se os nomes forem diferentes do padrão

**`ForbiddenError` no vault**
- Verifique se o seu usuário/SP tem a role **Key Vault Secrets User** no vault

---

**[← Autenticação](authentication.md)** | **[Voltar ao README](../README.md)**
