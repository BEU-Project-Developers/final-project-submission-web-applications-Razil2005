using FurnitureShopProjectRazil.Data; // AppDbContext üçün
using FurnitureShopProjectRazil.Models; // Blog modeli üçün
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // ToListAsync üçün
using System.Collections.Generic; // List<> üçün
using System.Linq; // OrderByDescending üçün
using System.Threading.Tasks; // async/await üçün

namespace FurnitureShopProjectRazil.Controllers
{
    public class BlogController : Controller
    {
        private readonly AppDbContext _context;

        public BlogController(AppDbContext context)
        {
            _context = context;
        }

       
        public async Task<IActionResult> Index()
        {
            // Bütün blog yazılarını tarixinə görə azalan sırada çəkirik
            List<Blog> blogPosts = await _context.Blogs
                                                 .OrderByDescending(b => b.Date)
                                                 .ToListAsync();

            return View(blogPosts); 
        }

        
    }
}