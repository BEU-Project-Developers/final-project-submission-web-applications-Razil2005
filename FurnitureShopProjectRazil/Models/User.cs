namespace FurnitureShopProjectRazil.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Fullname { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string Profession { get; set; }

        public UserRole UserRole { get; set; }
        public ICollection<Blog> Blogs { get; set; }
        public ICollection<Testimonial> Testimonials { get; set; }
    }
}
