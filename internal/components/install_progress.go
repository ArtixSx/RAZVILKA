package components

import "context"

// InstallStage is a closed vocabulary: telemetry never accepts process output,
// remote response bodies, filenames, URLs, package arguments or errors.
type InstallStage uint8

const (
	InstallPreflight InstallStage = iota
	installDependencies
	installUSQUENetwork
	installCatalog
	installMetadata
	installChecksum
	installDownload
	installArchive
	installOpkg
	installPublish
	installVerify
)

func (s InstallStage) Message() string {
	labels := [...]string{
		InstallPreflight:    "Проверяем условия установки",
		installUSQUENetwork: "Проверяем, свободны ли сетевые адреса для USQUE",
		installDependencies: "Проверяем зависимости компонента",
		installCatalog:      "Обновляем списки пакетов Entware",
		installMetadata:     "Получаем сведения о выпуске",
		installChecksum:     "Получаем контрольные суммы выпуска",
		installDownload:     "Загружаем файл компонента",
		installArchive:      "Проверяем содержимое загруженного файла",
		installOpkg:         "Устанавливаем пакет через opkg",
		installPublish:      "Записываем проверенные файлы компонента",
		installVerify:       "Проверяем результат установки",
	}
	if int(s) >= len(labels) {
		return ""
	}
	return labels[s]
}

type installProgressContextKey struct{}

func WithInstallProgress(ctx context.Context, report func(InstallStage)) context.Context {
	return context.WithValue(ctx, installProgressContextKey{}, report)
}

func reportInstall(ctx context.Context, stage InstallStage) {
	if ctx == nil {
		return
	}
	if report, ok := ctx.Value(installProgressContextKey{}).(func(InstallStage)); ok && report != nil {
		report(stage)
	}
}
