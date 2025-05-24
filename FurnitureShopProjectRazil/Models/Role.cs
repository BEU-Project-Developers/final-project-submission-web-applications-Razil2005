namespace FurnitureShopProjectRazil.Models
{
    public class Role
    {
        public int Id { get; set; }
        public string Rolename { get; set; }
        public ICollection<UserRole> UserRoles { get; set; }
    }
}
