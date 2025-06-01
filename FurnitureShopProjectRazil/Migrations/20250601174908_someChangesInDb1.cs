using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FurnitureShopProjectRazil.Migrations
{
    /// <inheritdoc />
    public partial class someChangesInDb1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Teams_Roles_RoleId",
                table: "Teams");

            migrationBuilder.DropForeignKey(
                name: "FK_Teams_Users_UserId",
                table: "Teams");

            migrationBuilder.DropForeignKey(
                name: "FK_Testimonials_Teams_TeamId",
                table: "Testimonials");

            migrationBuilder.DropForeignKey(
                name: "FK_Testimonials_Users_UserId",
                table: "Testimonials");

            migrationBuilder.DropIndex(
                name: "IX_Testimonials_TeamId",
                table: "Testimonials");

            migrationBuilder.DropIndex(
                name: "IX_Testimonials_UserId",
                table: "Testimonials");

            migrationBuilder.DropIndex(
                name: "IX_Teams_RoleId",
                table: "Teams");

            migrationBuilder.DropColumn(
                name: "TeamId",
                table: "Testimonials");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "Testimonials");

            migrationBuilder.DropColumn(
                name: "RoleId",
                table: "Teams");

            migrationBuilder.RenameColumn(
                name: "Note",
                table: "Testimonials",
                newName: "Content");

            migrationBuilder.RenameColumn(
                name: "UserId",
                table: "Teams",
                newName: "ProfessionId");

            migrationBuilder.RenameIndex(
                name: "IX_Teams_UserId",
                table: "Teams",
                newName: "IX_Teams_ProfessionId");

            migrationBuilder.AddColumn<string>(
                name: "AuthorFullName",
                table: "Testimonials",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthorTitle",
                table: "Testimonials",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "DatePosted",
                table: "Testimonials",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AlterColumn<string>(
                name: "Fullname",
                table: "Teams",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<string>(
                name: "PersonalNote",
                table: "Teams",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ImagePath",
                table: "Homes",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "Professions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Professions", x => x.Id);
                });

            migrationBuilder.AddForeignKey(
                name: "FK_Teams_Professions_ProfessionId",
                table: "Teams",
                column: "ProfessionId",
                principalTable: "Professions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Teams_Professions_ProfessionId",
                table: "Teams");

            migrationBuilder.DropTable(
                name: "Professions");

            migrationBuilder.DropColumn(
                name: "AuthorFullName",
                table: "Testimonials");

            migrationBuilder.DropColumn(
                name: "AuthorTitle",
                table: "Testimonials");

            migrationBuilder.DropColumn(
                name: "DatePosted",
                table: "Testimonials");

            migrationBuilder.DropColumn(
                name: "PersonalNote",
                table: "Teams");

            migrationBuilder.DropColumn(
                name: "ImagePath",
                table: "Homes");

            migrationBuilder.RenameColumn(
                name: "Content",
                table: "Testimonials",
                newName: "Note");

            migrationBuilder.RenameColumn(
                name: "ProfessionId",
                table: "Teams",
                newName: "UserId");

            migrationBuilder.RenameIndex(
                name: "IX_Teams_ProfessionId",
                table: "Teams",
                newName: "IX_Teams_UserId");

            migrationBuilder.AddColumn<int>(
                name: "TeamId",
                table: "Testimonials",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "UserId",
                table: "Testimonials",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AlterColumn<string>(
                name: "Fullname",
                table: "Teams",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(100)",
                oldMaxLength: 100);

            migrationBuilder.AddColumn<int>(
                name: "RoleId",
                table: "Teams",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_Testimonials_TeamId",
                table: "Testimonials",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_Testimonials_UserId",
                table: "Testimonials",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Teams_RoleId",
                table: "Teams",
                column: "RoleId");

            migrationBuilder.AddForeignKey(
                name: "FK_Teams_Roles_RoleId",
                table: "Teams",
                column: "RoleId",
                principalTable: "Roles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Teams_Users_UserId",
                table: "Teams",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Testimonials_Teams_TeamId",
                table: "Testimonials",
                column: "TeamId",
                principalTable: "Teams",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Testimonials_Users_UserId",
                table: "Testimonials",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
