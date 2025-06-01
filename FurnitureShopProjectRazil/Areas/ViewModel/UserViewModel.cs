// Areas/Admin/ViewModels/UserViewModel.cs
namespace FurnitureShopProjectRazil.Areas.Admin.ViewModels
{
    public class UserViewModel
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? ProfileImagePath { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }
}