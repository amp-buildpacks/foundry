// Copyright (c) The Amphitheatre Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package foundry

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/effect"
	"github.com/paketo-buildpacks/libpak/sbom"
	"github.com/paketo-buildpacks/libpak/sherpa"
)

type Solc struct {
	LayerContributor libpak.DependencyLayerContributor
	Logger           bard.Logger
	Executor         effect.Executor
}

func NewFoundry(dependency libpak.BuildpackDependency, cache libpak.DependencyCache) Solc {
	contributor := libpak.NewDependencyLayerContributor(dependency, cache, libcnb.LayerTypes{
		Build:  true,
		Cache:  true,
		Launch: true,
	})
	return Solc{
		LayerContributor: contributor,
		Executor:         effect.NewExecutor(),
	}
}

func (r Solc) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	r.LayerContributor.Logger = r.Logger
	return r.LayerContributor.Contribute(layer, func(artifact *os.File) (libcnb.Layer, error) {
		foundry := layer.Path
		bin := filepath.Join(foundry, "bin")

		file := filepath.Join(foundry, "foundry_init.sh")

		r.Logger.Bodyf("Copying to %s", filepath.Dir(file))
		if err := sherpa.CopyFile(artifact, file); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to copy %s to %s\n%w", artifact.Name(), file, err)
		}

		if err := os.Chmod(file, 0755); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to chmod %s\n%w", file, err)
		}

		r.Logger.Bodyf("Setting %s in PATH", bin)
		if err := os.Setenv("PATH", sherpa.AppendToEnvVar("PATH", ":", bin)); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to set $PATH\n%w", err)
		}

		// set foundryup env
		if err := os.Setenv("XDG_CONFIG_HOME", filepath.Join(foundry, "..")); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to set $XDG_CONFIG_HOME\n%w", err)
		}

		if err := os.Setenv("FOUNDRY_DIR", foundry); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to set $FOUNDRY_DIR\n%w", err)
		}

		args := []string{}

		// install foundryup
		if _, err := r.Execute(file, args); err != nil {
			return libcnb.Layer{}, err
		}

		// install forge
		foundryup := filepath.Join(bin, "foundryup")
		if _, err := r.Execute(foundryup, args); err != nil {
			return libcnb.Layer{}, err
		}

		// get version
		forge := filepath.Join(bin, "forge")
		args = []string{"--version"}
		buf, err := r.Execute(forge, args)
		if err != nil {
			return libcnb.Layer{}, err
		}
		version := strings.Split(strings.TrimSpace(buf.String()), " ")[1]
		r.Logger.Bodyf("Checking forge version: %s", version)

		// git init
		args = []string{"init"}
		if _, err := r.Execute("git", args); err != nil {
			return libcnb.Layer{}, err
		}

		// forge i
		args = []string{"install"}
		if _, err := r.Execute(forge, args); err != nil {
			return libcnb.Layer{}, err
		}

		sbomPath := layer.SBOMPath(libcnb.SyftJSON)
		dep := sbom.NewSyftDependency(layer.Path, []sbom.SyftArtifact{
			{
				ID:      "foundry",
				Name:    "Foundry",
				Version: version,
				Type:    "UnknownPackage",
				FoundBy: "amp-buildpacks/foundry",
				Locations: []sbom.SyftLocation{
					{Path: "amp-buildpacks/foundry/foundry/foundry.go"},
				},
				Licenses: []string{"Apache-2.0"},
				CPEs:     []string{fmt.Sprintf("cpe:2.3:a:foundry:foundry:%s:*:*:*:*:*:*:*", version)},
				PURL:     fmt.Sprintf("pkg:generic/foundry@%s", version),
			},
		})
		r.Logger.Debugf("Writing Syft SBOM at %s: %+v", sbomPath, dep)
		if err := dep.WriteTo(sbomPath); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to write SBOM\n%w", err)
		}
		return layer, nil
	})
}

func (r Solc) Execute(command string, args []string) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	if err := r.Executor.Execute(effect.Execution{
		Command: command,
		Args:    args,
		Stdout:  buf,
		Stderr:  buf,
	}); err != nil {
		return buf, fmt.Errorf("error executing '%s':\n Combined Output: %s: \n%w", command, buf.String(), err)
	}
	return buf, nil
}

func (r Solc) BuildProcessTypes(enableProcess string) ([]libcnb.Process, error) {
	processes := []libcnb.Process{}

	if enableProcess == "true" {
		processes = append(processes, libcnb.Process{
			Type:      "web",
			Command:   "forge",
			Arguments: []string{"test"},
			Default:   true,
		})
	}
	return processes, nil
}

func (r Solc) Name() string {
	return r.LayerContributor.LayerName()
}
