package app

import (
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engine"
)

// Merge independent installation facts without assigning ownership of a
// manually installed binary to our package/release installer.
func mergeComponentRuntimes(views []components.View, runtimes []engine.Status) {
	for i := range views {
		view := &views[i]
		for _, runtime := range runtimes {
			if view.ID != runtime.ID {
				continue
			}
			view.Configured, view.Running, view.ExternalOwner = runtime.Configured, runtime.Running, runtime.External
			view.RuntimeVersion = runtime.Version
			if runtime.Installed && !view.Installed {
				view.Installed = true
				view.InstalledVersion, view.InstalledVersionSource = runtime.Version, "runtime"
				view.UpdateAvailable = false // package version cannot be compared with an unowned runtime.
				view.CanInstall, view.CanUpdate, view.CanRemove = false, false, false
				prefix := "runtime"
				if view.Provider == "platform" {
					prefix = "platform"
				}
				view.State = prefix + "-installed"
				if runtime.Running {
					view.State = prefix + "-active"
				}
				view.LifecycleBlockReason = "Обход обнаружен на роутере вне управляемого пакета. Используйте установщик его владельца."
			}
			if runtime.External {
				view.CanInstall, view.CanUpdate, view.CanRemove = false, false, false
				view.LifecycleBlockReason = "Обход управляется внешним проектом."
				if runtime.Installed {
					view.State = "external-installed"
					if runtime.Running {
						view.State = "external-active"
					}
				}
			}
			if runtime.Running {
				view.CanInstall, view.CanUpdate, view.CanRemove = false, false, false
				view.LifecycleBlockReason = "Обход сейчас запущен. Сначала переключите его сервисы и примените изменения."
			}
			break
		}
	}
}

func enrichComponentRuntimePlan(plan *components.Plan, runtimes []engine.Status) {
	for _, runtime := range runtimes {
		if plan.Action != "remove" {
			for _, dependency := range plan.Dependencies {
				if runtime.ID == dependency.ID && !dependency.Installed && runtime.Installed {
					plan.AddBlocker("UNMANAGED_DEPENDENCY", "Зависимость уже установлена вне управляемого пакета: "+runtime.Name, "Проверьте владельца зависимости; её исполняемый файл не будет перезаписан.")
				}
			}
		}
		if runtime.ID != plan.Component {
			continue
		}
		if runtime.Running {
			plan.AddBlocker("RUNTIME_ACTIVE", "Обход сейчас активен", "Перенесите зависимые сервисы на другой маршрут, примените изменения и повторите операцию.")
		}
		if runtime.External {
			plan.AddBlocker("EXTERNAL_OWNER", "Обход и его сетевые ресурсы управляются внешним проектом", "Используйте мастер миграции ownership.")
		}
		if runtime.Installed && !plan.Installed {
			plan.Installed = true
			plan.InstalledVersion = runtime.Version
			plan.AddBlocker("UNMANAGED_RUNTIME", "Обход обнаружен вне управляемого пакета", "Используйте установщик владельца; наличие файла не даёт RAZVILKA права заменить или удалить его.")
		}
	}
}
