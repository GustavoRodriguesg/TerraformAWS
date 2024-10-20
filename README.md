<h1 align="center"> Projeto Terraform AWS - Infraestrutura Básica</h1>
<br>

Este projeto utiliza o **Terraform** para provisionar uma infraestrutura básica na **AWS**, composta por uma VPC, Subnet, Grupo de Segurança (Security Group), Key Pair e uma instância EC2. Além disso, a instância EC2 é configurada para instalar automaticamente o servidor **Nginx**.

<br>

**A AWS (Amazon Web Services)** é uma das plataformas de computação em nuvem mais populares do mundo, fornecendo uma ampla variedade de serviços baseados em nuvem, como armazenamento, processamento, banco de dados, redes e segurança. Esses serviços permitem que empresas e desenvolvedores criem, implantem e escalem aplicações sem precisar gerenciar fisicamente a infraestrutura.

<p align="center">
  <img src="https://appprod-br.ingrammicro.com/portal/wp-content/uploads/2019/10/banner-imnews-aws-e1571669988971-1030x405.png" alt="Descrição da Imagem" width="800" height="350"/>
</p>

**Terraform** é uma ferramenta de infraestrutura como código (IaC) desenvolvida pela HashiCorp, que permite aos usuários definir e provisionar infraestrutura em várias plataformas de nuvem por meio de arquivos de configuração declarativos.

<p align="center">
  <img src="https://media.licdn.com/dms/image/D4D12AQE3mp9nuWM-Qg/article-cover_image-shrink_600_2000/0/1708435857575?e=2147483647&v=beta&t=zCm2y3FVTo_a8l_fN67kXT4DBOhDQuFXXO_h32Xrg84" alt="Descrição da Imagem" width="800" height="350"/>
</p>

**Nginx** é um servidor web de código aberto que também pode atuar como um balanceador de carga, proxy reverso e cache. Ele é amplamente utilizado devido à sua alta performance, escalabilidade e baixo consumo de recursos.

<p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:1200/0*mjG1YdoT7xPcnznN.jpg" width="800" height="350"/>
</p>

## Instalar
[Site para instalar Terraform](https://developer.hashicorp.com/terraform/install)<br>
[Site para instalar AWS CLI](https://aws.amazon.com/pt/cli/)


## Instruções Iniciais

Se você não tiver uma conta na AWS, acesse o site da AWS e crie uma conta. Você vai precisar de um cartão de crédito para se inscrever, mas a AWS oferece um nível gratuito (AWS Free Tier), que permite criar e usar certos serviços gratuitamente por um tempo limitado.

[Site AWS](https://aws.amazon.com/pt/)

Depois de logado no sistema AWS acessar:https://aws.amazon.com/pt/iam/ crie um usuário e um grupo de permissão com acesso administrador (se não tiver) e guarde a sua Access key ID além da Secret access Key.
* Digite no Prompt de Comando da sua máquina:

```
aws configure
```
* Preencher com:

```
AWS Access Key ID [None]: Sua access Key ID
AWS Secret Access Key [None]: Sua Secret access Key
Default region name [None]: us-east-1
Default output format [None]: json
```

## Execução


(Recomendável utilizar um editor de código para abrir o projeto)

* Execute o comando abaixo para inicializar o projeto Terraform e baixar os provedores necessários:
```
terraform init
```

* Gere e revise o plano de criação da infraestrutura:
```
terraform plan
```

* Crie os recursos na AWS conforme o plano gerado:
```
terraform apply
```


## Código
### Provider
* Usar o provedor AWS da região ```us-east-1```(que corresponde à região Norte da Virgínia) para gerenciar os recursos:
```terraform
provider "aws" {
  region = "us-east-1"
}
```
### Variáveis
* A variável projeto define o nome do projeto e a variável candidato o nome do candidato. Elas são usadas na composição dos nomes dos recursos, tornando-os mais descritivos.
*  O nome da chave, VPC, subnet, gateway, route table e das instâncias é composto pelas variáveis ```terraform ${var.projeto}``` e ```terraform ${var.candidato}```:
```terraform
variable "projeto" {
  description = "Nome do projeto"
  type        = string
  default     = "VExpenses"
}

variable "candidato" {
  description = "Nome do candidato"
  type        = string
  default     = "SeuNome"
}
```
### Private Key 
* Esse bloco cria uma chave privada RSA de 2048 bits, que será usada para acessar a instância EC2 via SSH, o recurso ```tls_private_key``` gera uma chave privada que será usada para criar um Key Pair na AWS:
```terraform
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

```
### Key Pair

* O Terraform cria um par de chaves na AWS com base na chave pública gerada anteriormente:
```terraform
resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "${var.projeto}-${var.candidato}-key"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

```
### VPC

* Este bloco cria uma rede virtual VPC com o bloco de endereços CIDR 10.0.0.0/16, além do DNS support e DNS hostnames no estado ```true``` (ou seja, ativados):
```terraform
resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.projeto}-${var.candidato}-vpc"
  }
}

```
### Subnet

* Este bloco cria uma subnet dentro da VPC com o bloco CIDR 10.0.1.0/24 associada à zona de disponibilidade ```us-east-1a```:
```terraform
resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "${var.projeto}-${var.candidato}-subnet"
  }
}

```
### Gateway

* Este bloco cria um Gateway que permite que os recursos na VPC se conectem à internet:
```terraform
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-igw"
  }
}

```
### Route Table

* A Tabela de Rotas define as regras de roteamento para o tráfego na VPC, neste caso o tráfego (0.0.0.0/0) para o Internet Gateway, permitindo acesso à internet:
```terraform
resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table"
  }
}


```
### Table Association

* Associação da subnet criada anteriormente à tabela de rotas para garantir que a subnet siga as regras de roteamento definidas (incluindo acesso à internet via Internet Gateway):
```terraform
resource "aws_route_table_association" "main_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_route_table.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table_association"
  }
}

```
### AWS Security Group

* Grupo de segurança na AWS, que controla as regras de entrada e saída para recursos como instâncias EC2 com descrição do grupo, associação ao VPC ```vpc_id = aws_vpc.main_vpc.id```.
* ```ingress```: Define as regras de entrada, ou seja, o tráfego que é permitido entrar na instância.
* ```from_port = 22``` e ```to_port = 22```: Permite o tráfego na porta 22, que é usada para conexões SSH.
* ```protocol = "tcp"```: Especifica que o protocolo usado é TCP, o protocolo padrão para SSH.
* ```cidr_blocks = ["0.0.0.0/0"]```: Permite o tráfego de qualquer endereço IPv4, tornando o SSH acessível de qualquer local.
* ```ipv6_cidr_blocks = ["::/0"]```: Permite o tráfego de qualquer endereço IPv6.
* ```egress```: Define as regras de saída, ou seja, o tráfego que é permitido sair da instância.
* ```from_port = 0```, ```to_port = 0```, ```protocol = "-1"```: Permite todo o tráfego de saída (todos os protocolos e portas).
```terraform
resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Permitir SSH de qualquer lugar e todo o tráfego de saída"
  vpc_id      = aws_vpc.main_vpc.id

  # Regras de entrada
  ingress {
    description      = "Allow SSH from anywhere"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # Regras de saída
  egress {
    description      = "Allow all outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-sg"
  }
}


```
### (AMI)

* Este bloco encontra a Amazon Machine Image (AMI) mais recente do Debian 12 com o filtro ```name``` busca AMIs com o padrão ```debian-12-amd64-*```, e a  propriedade ```most_recent = true``` garante que a AMI mais atual será selecionada, ```name = "virtualization-type"```: Filtro baseado no tipo de virtualização, e ```values = ["hvm"]``` seleciona apenas AMIs com virtualização HVM (Hardware Virtual Machine):
```values = ["hvm"]```: Seleciona apenas AMIs com virtualização HVM (Hardware Virtual Machine)
```terraform
data "aws_ami" "debian12" {
  most_recent = true

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["679593333241"]
}

```
### Instancia EC2

* Este bloco de código cria uma instância EC2 na AWS utilizando a AMI do Debian 12, do tipo t2.micro, associada a uma sub-rede e um grupo de segurança previamente definidos:
 ```terraform

  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.name]

```

* ```associate_public_ip_address = true ``` Indica que a instância deverá ter um endereço IP público associado. Isso permite que a instância seja acessível pela internet.
Disco em 20 GB do tipo GP2 (General Purpose SSD), e quando a instância for excluída, o volume (disco) será automaticamente excluído.
 ```terraform

  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }

```

* ```user_data```: Define um script de inicialização que será executado automaticamente quando a instância for lançada.

* ```apt-get update -y```: Atualiza a lista de pacotes disponíveis no Debian.

* ```apt-get upgrade -y```: Atualiza os pacotes instalados para suas versões mais recentes.
```terraform
resource "aws_instance" "debian_ec2" {
  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.name]

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get upgrade -y
              EOF

  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }
}

```
### Saídas

* A primeira saída, ```private_key```, exibe a chave privada usada para acessar a instância via SSH com ```sensitive = true```(ou seja, o Terraform não exibirá esse valor no console), já a segunda, ```ec2_public_ip```, fornece o endereço IP público da instância EC2:
```terraform
output "private_key" {
  description = "Chave privada para acessar a instância EC2"
  value       = tls_private_key.ec2_key.private_key_pem
  sensitive   = true
}

output "ec2_public_ip" {
  description = "Endereço IP público da instância EC2"
  value       = aws_instance.debian_ec2.public_ip
}

```
## Mudanças
### Definição das variáveis
* A primeira mudança é na definição das variáveis candidato e projeto para o funcionamento do código:
```terraform

variable "projeto" {
  description = "ProjetoAWS"
  type        = string
  default     = "VExpenses"
}

variable "candidato" {
  description = "GustavoRodrigues"
  type        = string
  default     = "GustavoRodrigues"
}
```
### Nginx
[Documenção NGINX](https://nginx.org/en/docs/)
```terraform

  resource "aws_instance" "debian_ec2" {
  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.name]

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }

  # Script para instalar o Nginx
  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y nginx
              systemctl start nginx
              systemctl enable nginx
              EOF

  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }
}
```
* ```apt-get update -y```: Atualiza a lista de pacotes disponíveis.
* ```apt-get install -y nginx```: Instala o servidor web Nginx.
* ```systemctl start nginx```: Inicia o serviço do Nginx imediatamente.
* ```systemctl enable nginx```: Configura o Nginx para iniciar automaticamente sempre que a instância for reiniciada.

```terraform

resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Permitir SSH e HTTP de qualquer lugar e todo o tráfego de saída"
  vpc_id      = aws_vpc.main_vpc.id

  # Permitir SSH de qualquer lugar
  ingress {
    description      = "Allow SSH from anywhere"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # Permitir HTTP de qualquer lugar
  ingress {
    description      = "Allow HTTP traffic"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # Regras de saída (egress)
  egress {
    description      = "Allow all outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-sg"
  }
}
```

* O Security Group foi configurado para permitir tráfego na porta 80 (HTTP), permitindo que acesse o servidor Nginx via navegador.
* Novo tipo de saída:
```terraform

# Url de acesso ao Nginx
output "nginx_url" {
  description = "URL de acesso ao Nginx"
  value       = "http://${aws_instance.debian_ec2.public_ip}"
}
```
* Digite  no navegador o endereço IP que será mostrado na saída da instância.

### Restringir o acesso SSH

* Restringir o acesso SSH apenas ao seu IP aumenta a segurança. Para isso foi adicionado a variável ```allowed_ssh_ip``` que armazena o IP de acesso so serviço (ex:192.168.1.100/32):
```terraform

variable "allowed_ssh_ip" {
  description = "IP público permitido para conexões SSH"
  type        = string
  default     = "192.168.1.100/32" # Substitua pelo seu IP público
}
```
* Mudança na ```aws_security_group``` em sua descrição, e na utlização da variável ```var.allowed_ssh_ip``` em ```cidr_blocks``` para restringir a entrada SSH:
```terraform

resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Permitir SSH restrito e permitir todo o tráfego de saída"
  vpc_id      = aws_vpc.main_vpc.id

  # Regras de entrada
  ingress {
    description      = "Allow SSH from specific IP"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = [var.allowed_ssh_ip]  # Restringir ao IP permitido
  }
  # Tráfego HTTP

  ingress {
    description      = "Allow HTTP traffic"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
   # Regras de saída
  egress {
    description      = "Allow all outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-sg"
  }
}
```
### Melhorar a Política de Senha SSH
* Aumentar o número de bits da chave RSA de 2048 para 4096 bits eleva a segurança da autenticação via SSH:
```terraform

resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 4096 # Aumento na quantidade de bits
}
```
