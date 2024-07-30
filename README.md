# Overview

This library is created for helping Kubernetes related libraries and tools to parse Kubernetes taints. Code for parsing the taints is directly copied from the Kubernetes source code. 

## Why?

To prevent depending on the main Kubernetes Go module by other libraries and tools. Depending on the main Kubernetes Go module breaks IDE integration (GoLand) and it is discouraged by the Kubernetes project maintainers (see [this comment](https://github.com/kubernetes/kubernetes/issues/79384#issuecomment-505627280)).

## Acknowledgments

This project uses code from the [Kubernetes project](https://github.com/kubernetes/kubernetes), which is licensed under the Apache License 2.0.
