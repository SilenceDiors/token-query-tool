# 推送到 GitHub 的步骤

## 1. 初始化 Git 仓库

```bash
cd /Users/silenchen/token-query-tool
git init
```

## 2. 添加所有文件

```bash
git add .
```

## 3. 提交代码

```bash
git commit -m "Initial commit: Multi-chain token query tool"
```

## 4. 在 GitHub 上创建新仓库

1. 访问 https://github.com/new
2. 填写仓库名称（例如：`token-query-tool`）
3. 选择 Public 或 Private
4. **不要**勾选 "Initialize this repository with a README"（因为本地已有）
5. 点击 "Create repository"

## 5. 添加远程仓库并推送

将下面的 `<your-username>` 和 `<repository-name>` 替换为你的实际信息：

```bash
# 添加远程仓库
git remote add origin https://github.com/<your-username>/<repository-name>.git

# 或者使用 SSH（如果你配置了SSH密钥）
# git remote add origin git@github.com:<your-username>/<repository-name>.git

# 推送代码
git branch -M main
git push -u origin main
```

## 示例

假设你的GitHub用户名是 `silenchen`，仓库名是 `token-query-tool`：

```bash
git remote add origin https://github.com/silenchen/token-query-tool.git
git branch -M main
git push -u origin main
```

## 后续更新

以后如果有代码更新，使用以下命令：

```bash
git add .
git commit -m "描述你的更改"
git push
```

## 注意事项

- `.gitignore` 文件已经配置好，会自动排除临时文件、生成的zip文件等
- 如果遇到认证问题，可能需要配置 GitHub 的 Personal Access Token
- 如果使用 SSH，确保已配置 SSH 密钥
