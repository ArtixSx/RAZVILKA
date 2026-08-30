package routeidentity

// Explanation keeps config values, process arguments and credentials out of UI.
func Explanation(code string) string {
	switch code {
	case "route-receipt-missing":
		return "Нет записи управляемого запуска. Сторонний или ранее запущенный процесс не перезапускается автоматически; повторная проверка пути доступна после его запуска через RAZVILKA новой версии."
	case "route-direct-outbound":
		return "В профиле выбран выход напрямую (DIRECT), а не удалённый обход. Выберите удалённый узел."
	case "route-rules-unverified", "route-dynamic-config-unverified", "route-chain-unverified", "route-outbound-unsupported":
		return "Для правил, цепочки или автоматического выбора узла пока нет проверки точного выхода. Для однозначного теста используйте отдельный профиль одного удалённого узла."
	case "route-runtime-changed":
		return "Процесс или конфигурация изменились после запуска либо во время проверки. Повторите проверку после завершения изменения."
	case "route-listener-owner-mismatch", "route-listener-ambiguous", "route-engine-mismatch", "route-command-unverified":
		return "Проверяемый прокси-порт не удалось однозначно связать с выбранным процессом и профилем. Проверьте конфликт портов и способ запуска."
	default:
		return "Не хватает данных о процессе, конфигурации или прокси-порте. Это не доказывает, что сервис недоступен."
	}
}
