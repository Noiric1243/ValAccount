# 发布检查

上传仓库的文件：

- `README.md`
- `.gitignore`、`.gitattributes`
- `build.ps1`
- `src/Manager.cs`、`src/app.manifest`
- `scripts/Generate-Icon.ps1`、`scripts/Test.ps1`
- `assets/VALO.ico`、`assets/VALO-icon.png`
- `docs/RELEASE.md`、`docs/VALIDATION.md`

不要上传 `data`、`diagnostics`、`.vault`、备份或个人日志。通过网页上传前也需要手动检查，网页上传不会应用本机的 .gitignore 筛选。

构建、测试通过后，`bin/VALO.exe` 可单独作为 Release 附件。EXE 无代码签名，可能出现未知发布者提示；不要要求使用者关闭系统防护。

仓库尚未指定开源许可证。若要允许其他人复用、修改和分发，请由作者选择许可证后再添加 LICENSE。
