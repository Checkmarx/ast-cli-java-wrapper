<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="">
    <img src="https://raw.githubusercontent.com/Checkmarx/ci-cd-integrations/main/.images/cx_x_icon.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">AST-CLI-JAVA-WRAPPER</h3>

<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#setting-up">Setting Up</a></li>
      </ul>
    </li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

The Java-Wrapper is part of the AST-CLI project that provides a shared infrastructure across the AST projects. 
It contains technology neutral repository interfaces as well as a metadata model for persisting Java classes.

<!-- GETTING STARTED -->
## Getting Started

#### Maven configuration

Add the Maven dependency:

        <dependency>
            <groupId>com.checkmarx.ast</groupId>
            <artifactId>ast-cli-java-wrapper</artifactId>
            <version>1.0.14</version>
        </dependency>



### Prerequisites

To be able to build the code you should have:
* Java (version above 1.8)

* Maven (version above 3)


### Setting Up

In your terminal, run:
```
- mvn clean install
```

To run integrations tests, you need to set up environment variables:

- In Linux systems run in terminal:
```
export CX_CLIENT_ID="{value}"
export CX_CLIENT_SECRET="{value}"
export CX_APIKEY="{value}"
export CX_BASE_URI="{value}"
export CX_BASE_AUTH_URI="{value}"
export CX_TENANT="{value}"
export PATH_TO_EXECUTABLE="{value}"
```

- In Windows systems run in powershell:
```
setx CX_CLIENT_ID {value}
setx CX_CLIENT_SECRET {value}
setx CX_APIKEY {value}
setx CX_BASE_URI {value}
setx CX_BASE_AUTH_URI {value}
setx CX_TENANT {value}
setx PATH_TO_EXECUTABLE {value}
```
<!-- CONTACT -->
## Contact

Checkmarx - AST Integrations Team

Project Link: [https://github.com/CheckmarxDev/ast-cli-java-wrapper](https://github.com/CheckmarxDev/ast-cli-java-wrapper)


© 2021 Checkmarx Ltd. All Rights Reserved.
