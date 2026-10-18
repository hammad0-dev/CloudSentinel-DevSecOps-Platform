output "vpc_id" { value = aws_vpc.this.id }
output "public_subnet_id" { value = aws_subnet.public.id }
output "private_subnet_id" { value = aws_subnet.private.id }
output "internet_gateway_id" { value = aws_internet_gateway.this.id }
output "public_route_table_id" { value = aws_route_table.public.id }
output "private_route_table_id" { value = aws_route_table.private.id }
output "public_security_group_id" { value = aws_security_group.public.id }
output "private_security_group_id" { value = aws_security_group.private.id }
