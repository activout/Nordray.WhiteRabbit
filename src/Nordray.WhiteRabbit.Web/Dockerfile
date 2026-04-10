FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Nordray.WhiteRabbit.sln ./
COPY src/Nordray.WhiteRabbit.Core/Nordray.WhiteRabbit.Core.csproj                         src/Nordray.WhiteRabbit.Core/
COPY src/Nordray.WhiteRabbit.Bunny/Nordray.WhiteRabbit.Bunny.csproj                       src/Nordray.WhiteRabbit.Bunny/
COPY src/Nordray.WhiteRabbit.Infrastructure/Nordray.WhiteRabbit.Infrastructure.csproj     src/Nordray.WhiteRabbit.Infrastructure/
COPY src/Nordray.WhiteRabbit.AuthProxy/Nordray.WhiteRabbit.AuthProxy.csproj               src/Nordray.WhiteRabbit.AuthProxy/
COPY src/Nordray.WhiteRabbit.Proxy/Nordray.WhiteRabbit.Proxy.csproj                       src/Nordray.WhiteRabbit.Proxy/
COPY src/Nordray.WhiteRabbit.Web/Nordray.WhiteRabbit.Web.csproj                           src/Nordray.WhiteRabbit.Web/
COPY tests/Nordray.WhiteRabbit.Tests.Unit/Nordray.WhiteRabbit.Tests.Unit.csproj           tests/Nordray.WhiteRabbit.Tests.Unit/
COPY tests/Nordray.WhiteRabbit.Tests.Integration/Nordray.WhiteRabbit.Tests.Integration.csproj tests/Nordray.WhiteRabbit.Tests.Integration/

RUN dotnet restore

COPY . .

RUN dotnet publish src/Nordray.WhiteRabbit.Web/Nordray.WhiteRabbit.Web.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "Nordray.WhiteRabbit.Web.dll"]
